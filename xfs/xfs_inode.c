// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include <linux/iversion.h>

#include "xfs_platform.h"
#include <linux/hashtable.h>	/* CREATEINT task registry */
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
#include "xfs_mxfs_dirshard.h"	/* shard-aware inactivation + rmdir emptiness */
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
 *  — P192: RE-CHECK THE EXTENT-MAP PREDICATE UNDER THE
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
 * peer-committed on-disk image (see the comment in xfs_dir_lookup,
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
			mxfs_probe_ratelimited(
				"mxfs: P192-ILOCK-MAP-RACE ino=%llu fork=%s fmt=%d nextents=%llu comm=%s — fork needed an iread AFTER xfs_ilock returned SHARED (DLM acquire hook reloaded the inode); upgrading to EXCL\n",
				(unsigned long long)ip->i_ino, which,
				ifp->if_format,
				(unsigned long long)ifp->if_nextents,
				current->comm);
	}

	/* leak-C fix: preserve ALL mxfs policy bits across the base-mode
	 * replacement, not just PRIREAD.  Dropping CREATEINT here regressed the
	 * reacquire to wire PR (PRIREAD) right after the EX was granted. */
	new_mode = XFS_ILOCK_EXCL |
		   (lock_mode & (XFS_ILOCK_MXFS_PRIREAD |
				 XFS_ILOCK_MXFS_CREATEINT));
	if (unlikely((lock_mode & XFS_ILOCK_MXFS_CREATEINT) &&
		     mxfs_instr_enabled))
		mxfs_probe_ratelimited("mxfs: P-CI-C recheck-under-arm ino=%llu (CREATEINT preserved across relock)\n",
			(unsigned long long)ip->i_ino);
	xfs_iunlock(ip, lock_mode);
	xfs_ilock(ip, new_mode);
	return new_mode;
}

/*
 * CREATE-INTENT registry (FIX-26 task-registry pattern): xfs_lookup
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
 * (design review review): single gate+consult used by EVERY lock-mode
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
/*
 * The lock mode a data-fork map read needs, with the MXFS policy tags it
 * carries.  Shared between the plain acquire below and the fallible one the
 * readdir path uses, so the two cannot drift.
 */
static uint
xfs_ilock_data_map_mode(
	struct xfs_inode	*ip)
{
	uint			lock_mode = XFS_ILOCK_SHARED;
	/* leak-B fix: consult ONCE, apply the tag AFTER the base mode
	 * is final.  The old order set CREATEINT on SHARED and the need_iread
	 * branch's `lock_mode = XFS_ILOCK_EXCL` wiped it, regressing every
	 * fresh-adopt create-intent lookup to wire PR (PRIREAD) — preserving
	 * the per-visit PR->EDEADLK->drain->EX cycle CREATEINT exists to kill. */
	bool			ci = mxfs_createint_dir_armed(ip);

	if (xfs_need_iread_extents(&ip->i_df)) {
		lock_mode = XFS_ILOCK_EXCL;
		/*
		 * iread-PR (PROVEN BY INSTRUMENT root of the
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
			mxfs_probe_ratelimited("mxfs: P-CI-B iread-under-arm ino=%llu (CREATEINT preserved over PRIREAD)\n",
				(unsigned long long)ip->i_ino);
	}
	if (unlikely(ci))
		lock_mode |= XFS_ILOCK_MXFS_CREATEINT;
	return lock_mode;
}

uint
xfs_ilock_data_map_shared(
	struct xfs_inode	*ip)
{
	uint			lock_mode = xfs_ilock_data_map_mode(ip);

	xfs_ilock(ip, lock_mode);
	lock_mode = mxfs_ilock_map_recheck(ip, &ip->i_df, lock_mode, "data");
	return lock_mode;
}

/*
 * 0.84.4: the same acquire for a caller that may be refused (readdir).  The
 * cluster grant under either xfs_ilock here can be abandoned — the master
 * never acknowledged the request past the budget, or the task was killed —
 * and the verdict is read at each acquisition, before anything that needs
 * the grant runs: the map recheck's relock is a second acquisition and is
 * asked separately, so a refused first lock never turns into a second wait.
 * 0 with *lock_mode holding what was taken; -EIO/-EINTR with nothing held
 * and *lock_mode == 0.
 */
int
xfs_ilock_data_map_shared_fallible(
	struct xfs_inode	*ip,
	uint			*lock_mode)
{
	uint			mode = xfs_ilock_data_map_mode(ip);
	int			error;

	*lock_mode = 0;
	error = mxfs_ilock_fallible(ip, mode);
	if (error)
		return error;
	if (mxfs_ilock_map_recheck_enabled && (mode & XFS_ILOCK_SHARED) &&
	    xfs_need_iread_extents(&ip->i_df)) {
		uint		new_mode = XFS_ILOCK_EXCL |
					   (mode & (XFS_ILOCK_MXFS_PRIREAD |
						    XFS_ILOCK_MXFS_CREATEINT));

		xfs_iunlock(ip, mode);
		error = mxfs_ilock_fallible(ip, new_mode);
		if (error)
			return error;
		mode = new_mode;
	}
	*lock_mode = mode;
	return 0;
}

/*
 * The lock mode an attr-fork map read needs, shared between the plain
 * acquire and the fallible one the xattr readers use, so the two cannot
 * drift.
 */
static uint
xfs_ilock_attr_map_mode(
	struct xfs_inode	*ip)
{
	uint			lock_mode = XFS_ILOCK_SHARED;

	if (xfs_inode_has_attr_fork(ip) && xfs_need_iread_extents(&ip->i_af)) {
		lock_mode = XFS_ILOCK_EXCL;
		/* iread-PR — same as the data-fork
		 * variant above: attr-fork extent load needs only cluster PR. */
		if (mxfs_iread_pr && ip->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
			lock_mode |= XFS_ILOCK_MXFS_PRIREAD;
	}
	return lock_mode;
}

uint
xfs_ilock_attr_map_shared(
	struct xfs_inode	*ip)
{
	uint			lock_mode = xfs_ilock_attr_map_mode(ip);

	xfs_ilock(ip, lock_mode);
	lock_mode = mxfs_ilock_map_recheck(ip, &ip->i_af, lock_mode, "attr");
	return lock_mode;
}

/*
 * 0.84.19: the attr-fork acquire for a caller that may be refused — the
 * extended-attribute readers (xfs_attr_get, xfs_attr_list), which hold no
 * transaction and have nothing dirty.  Same contract as the data-fork
 * variant: the cluster grant under either xfs_ilock may be abandoned, the
 * verdict is read at each acquisition before anything under the grant is
 * touched, and the map recheck's relock is a second acquisition asked
 * separately.  0 with *lock_mode holding what was taken; -EIO/-EINTR with
 * nothing held and *lock_mode == 0.
 */
int
xfs_ilock_attr_map_shared_fallible(
	struct xfs_inode	*ip,
	uint			*lock_mode)
{
	uint			mode = xfs_ilock_attr_map_mode(ip);
	int			error;

	*lock_mode = 0;
	error = mxfs_ilock_fallible(ip, mode);
	if (error)
		return error;
	if (mxfs_ilock_map_recheck_enabled && (mode & XFS_ILOCK_SHARED) &&
	    xfs_inode_has_attr_fork(ip) && xfs_need_iread_extents(&ip->i_af)) {
		uint		new_mode = XFS_ILOCK_EXCL |
					   (mode & XFS_ILOCK_MXFS_PRIREAD);

		xfs_iunlock(ip, mode);
		error = mxfs_ilock_fallible(ip, new_mode);
		if (error)
			return error;
		mode = new_mode;
	}
	*lock_mode = mode;
	return 0;
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
	/* XFS_ILOCK_MXFS_PRIREAD rides outside
	 * XFS_LOCK_MASK and is valid only alongside ILOCK_EXCL. */
	ASSERT(!(lock_flags & XFS_ILOCK_MXFS_PRIREAD) ||
	       (lock_flags & XFS_ILOCK_EXCL));
	/* CREATEINT rides outside the mask too; valid only with an
	 * ILOCK (shared or excl) — it upgrades the CLUSTER mode, never the
	 * local lock. */
	ASSERT(!(lock_flags & XFS_ILOCK_MXFS_CREATEINT) ||
	       (lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)));
	/* 0.87.23: NOEND rides outside the mask too; it is an unlock-only
	 * tag (a fallible acquire releasing components whose cluster
	 * request gave up), valid only alongside an ILOCK or IOLOCK. */
	ASSERT(!(lock_flags & XFS_ILOCK_MXFS_NOEND) ||
	       (lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL |
			      XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_SUBCLASS_MASK |
			       XFS_ILOCK_MXFS_PRIREAD |
			       XFS_ILOCK_MXFS_CREATEINT |
			       XFS_ILOCK_MXFS_NOEND)) == 0);
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
void
xfs_ilock(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock(ip, lock_flags, _RET_IP_);

	xfs_lock_flags_assert(lock_flags);

	/*
	 * (b61r6 holder-stack proof, instrumented): the IOLOCK
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
		/* iread-PR: an ILOCK_EXCL tagged
		 * PRIREAD serializes only the local extent-map load — the
		 * cluster needs PR, not EX (see xfs_ilock_data_map_shared).
		 * Never demote a combined IOLOCK_EXCL request. */
		if (unlikely(lock_flags & XFS_ILOCK_MXFS_PRIREAD) &&
		    !(lock_flags & XFS_IOLOCK_EXCL))
			mode = MXFS_LOCK_PR;
		/* CREATEINT: create-intent dir lookup wants the cluster
		 * at EX from the lookup on (kills the per-create PR->EDEADLK->
		 * drain->EX cycle).  Wins over PRIREAD by ordering. */
		if (unlikely(lock_flags & XFS_ILOCK_MXFS_CREATEINT))
			mode = MXFS_LOCK_EX;
		/*
		 * P100: capture the call path that takes a WRITE lock on
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
			mxfs_probe_ratelimited("mxfs: P100 EX-on-peer-file ino=%llu ino_ag=%u node_slot=%u lock_flags=0x%x\n",
				(unsigned long long)ip->i_ino,
				XFS_INO_TO_AGNO(p100mp, ip->i_ino),
				p100mp->m_mxfs_node_slot, lock_flags);
			if (atomic_inc_return(&p100_dumped) <= 3)
				mxfs_probe_stack();
		  } }
		mxfs_dlm_ilock_begin(ip, mode);
		/* D-0532 arm: park a genuine IOLOCK_EXCL holder after
		 * its admission (no-op unless armed for this inode). */
		if (unlikely(lock_flags & XFS_IOLOCK_EXCL)) {
			extern void mxfs_dbg_iolock_hold(struct xfs_inode *);
			mxfs_dbg_iolock_hold(ip);
		}
	}

	if (lock_flags & XFS_MMAPLOCK_EXCL) {
		down_write_nested(&VFS_I(ip)->i_mapping->invalidate_lock,
				  XFS_MMAPLOCK_DEP(lock_flags));
	} else if (lock_flags & XFS_MMAPLOCK_SHARED) {
		down_read_nested(&VFS_I(ip)->i_mapping->invalidate_lock,
				 XFS_MMAPLOCK_DEP(lock_flags));
	}

	/*
	 * diagnostic busy-spin ILOCK acquire REVERTED (sess-tcp): the
	 * trylock+cond_resched spin was a "revert after capture" diagnostic that
	 * severely distorts lock timing and starves peers — restored to the
	 * standard sleeping nested acquire so 2-node timing is trustworthy.
	 */
	if (lock_flags & XFS_ILOCK_EXCL)
		down_write_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));
	else if (lock_flags & XFS_ILOCK_SHARED)
		down_read_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));

	mxfs_ilk_note_lock(ip, lock_flags, _RET_IP_);
	/* writer-quiescence census — open-coded (NOT in note_lock:
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
/* (instrumented): ILOCK last-locker forensics — the 16-node create-storm
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
		/* writer-quiescence census.  Both callers (xfs_iunlock,
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

/*
 * (D-0532): release locks that xfs_ilock_nowait took WITHOUT a DLM
 * begin (ILOCK nowait never enters mxfs_dlm_ilock_begin — atomic-context
 * callers), so the release must not run mxfs_dlm_ilock_end either.  The
 * plain xfs_iunlock does, and on an inode still carrying a cached grant
 * (a DEFERRED-freed corpse being recycled for a new incarnation,
 * xfs_iget_recycle) that end is unpaired: P71-UNDERFLOW, then the end's
 * BAST/flush machinery runs at zero holders under a task that still owns
 * the ILOCK_EXCL rwsem.  Same body as the set-lock backoff's raw release.
 */
static void mxfs_iunlock_rwsems_raw(struct xfs_inode *ip, uint lock_flags);
void
xfs_iunlock_nodlm(
	struct xfs_inode	*ip,
	uint			lock_flags)
{
	mxfs_iunlock_rwsems_raw(ip, lock_flags);
}

int
xfs_ilock_nowait(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock_nowait(ip, lock_flags, _RET_IP_);

	xfs_lock_flags_assert(lock_flags);

	/*
	 * rwsem-first here too (mirrors xfs_ilock's b61r6
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
	/* writer-quiescence census (see xfs_ilock) */
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

	/* MXFS DLM: decrement holders, process deferred BAST if last.
	 * 0.87.23: not when the caller says no end is owed — a fallible
	 * acquire whose cluster request gave up took these components with
	 * no holder counted (XFS_ILOCK_MXFS_NOEND). */
	if (ip->i_mount->m_mxfs_dlm &&
	    !(lock_flags & XFS_ILOCK_MXFS_NOEND) &&
	    (lock_flags & (XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED |
			   XFS_ILOCK_EXCL | XFS_ILOCK_SHARED))) {
		uint8_t mode = (lock_flags & (XFS_IOLOCK_EXCL | XFS_ILOCK_EXCL)) ?
			MXFS_LOCK_EX : MXFS_LOCK_PR;
		/* iread-PR: mirror xfs_ilock's mapping
		 * so the PR holder count taken at begin is the one released. */
		if (unlikely(lock_flags & XFS_ILOCK_MXFS_PRIREAD) &&
		    !(lock_flags & XFS_IOLOCK_EXCL))
			mode = MXFS_LOCK_PR;
		/* CREATEINT: mirror xfs_ilock so the EX holder count
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
		/* writer-quiescence census: EXCL became SHARED (no
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
 * FIX-L3 (a9a03929) helpers for the set-lock functions below.
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
	 * FIX-L3 (a9a03929, k1 2/tcp tds wedge) — Phase A: acquire
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
			 * FIX-L3: Phase-A members take their rwsems via
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
		 * on — FIX-L3). */
		/*
		 * PROVEN BY INSTRUMENT FIX (xfs_rename / comm=mv
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
			/*
			 * lesson retained: xfs_ilock_nowait takes ONLY
			 * the rwsem.  A dir modified at a stale cached mode
			 * loses its commits to the P119-NONEX flush skip, so
			 * every member reaching here must already carry DLM
			 * authority — Phase A holds it (dlm_pre, FIX-L3 all
			 * members).
			 */
			ASSERT(!((lock_mode & XFS_ILOCK_EXCL) &&
				 S_ISDIR(VFS_I(ips[i])->i_mode)) || dlm_pre[i]);
			if (xfs_ilock_nowait(ips[i],
					     xfs_lock_inumorder(lock_mode, i)))
				continue;
		}

		/*
		 * Unlock all previous guys and try again.  xfs_iunlock will try
		 * to push the tail if the inode is in the AIL.  Phase-A members
		 * release only the RAW rwsems — their DLM hold persists so the
		 * grant cannot be forfeited mid-set (FIX-L3).
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
	 * FIX-L3 (a9a03929) — Phase A: BOTH inodes' cross-node DLM
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
		 * ABBA breaker (PROVEN BY INSTRUMENT, 184s cycle):
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
					mxfs_probe_ratelimited(
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
		 * PROVEN BY INSTRUMENT FIX for the tcp_dlm_scaling
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
		 * FIX-L3 (a9a03929, k1 2/tcp tds wedge): BOTH inodes'
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
	/*
	 * 0.84.24: one coordinated PR acquire per lookup for a stale-flagged
	 * shell whose slot reads FREE on the platter (see the ISTALE_CAW arm).
	 * Counted apart from evict_tries: it is not a retry, it is the read
	 * that makes the first judgement sound.
	 */
	int			reuse_coord = 0;
	/*
	 * (D-0941): the poisoned-shell retire arm gets its OWN counter.
	 * It shares nothing with evict_tries, which the ISTALE_CAW arm below
	 * also increments -- an inode that passed through both used to arrive
	 * at the poison arm with part of its budget already spent by a
	 * different retry (observed: a shell that printed try=1, try=2 and then
	 * "tries=5").  Two independent retry policies must not share one
	 * counter, and this arm's policy is about to differ from the other's.
	 */
	int			poison_tries = 0;
	/*
	 * (D-0941): drain-assisted retirement retries, counted apart from
	 * poison_tries because they answer a different question.  poison_tries
	 * bounds how long we wait for a reference to drop; this bounds how many
	 * times we act on having WATCHED one drop.  Kept separate so a shell that
	 * is genuinely pinned still fails closed after one bounded observation
	 * instead of looping on a reference that never leaves.
	 */
	int			poison_drains = 0;
	extern int		mxfs_icluster_dlm;
	int			igetmiss_tries = 0;
	int			gcwait_tries = 0;
	/* P-LKERR tripwire, review-designed: the
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
	 *  (Phase A): this dir shell is a POISONED dead
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
	 * magic diagnostic name — dump this dir's per-block
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
	 * consumer-side eager dir-block refresh BEFORE the lookup reads
	 * the dir blocks.  If a peer modified this dir since our last refresh,
	 * drop all clean cached dir DATA blocks so xfs_dir_lookup refetches the
	 * peer's durable committed image instead of a stale-stamped cached block
	 * (the unlink/create-visibility residual).  No-op single-node / unchanged
	 * dir / shortform.
	 */
	if (create_intent && dp->i_mount->m_mxfs_dlm) {
		mxfs_createint_enter(&createint_ent, dp->i_ino);
		createint_armed = true;
		/* (design review discriminator): the cached grant mode AT ARM
		 * ENTRY tells a residual EDEADLK's origin apart — a PR taken
		 * INSIDE the armed window (leaks A/B/C, fixable by tagging)
		 * vs a PR already cached from an earlier PLAIN lookup on this
		 * dir (path-walk/revalidate; needs a different fix). */
		if (unlikely(mxfs_instr_enabled))
			mxfs_probe_ratelimited("mxfs: P-CI-ARM ino=%llu cached_dlm_mode=%u\n",
				(unsigned long long)dp->i_ino, dp->i_dlm_mode);
	}
	/*
	 * 0.84.13 (D-0958): the lookup is a fallible boundary — nothing dirty,
	 * no transaction, the VFS holding only the parent's i_rwsem.  Both of
	 * its acquires of the parent (the consumer refresh and the directory
	 * read) may now be refused when a live master never acknowledged the
	 * request past the budget or this task was killed; the path walk then
	 * fails with that errno instead of restarting the wait for ever.  The
	 * child's iget below keeps its own retry ladder.
	 */
	if (dp->i_mount->m_mxfs_dlm) {
		error = mxfs_dlm_dir_consumer_refresh_lookup(dp);
		if (unlikely(error)) {
			if (createint_armed) {
				mxfs_createint_exit(&createint_ent);
				createint_armed = false;
			}
			lk_stage = 1;
			goto out_unlock;
		}
		error = mxfs_dir_lookup_fallible(dp, name, &inum, ci_name,
						 &dirent_ftype);
	} else {
		mxfs_dlm_dir_consumer_refresh(dp);
		error = xfs_dir_lookup(NULL, dp, name, &inum, ci_name,
				       &dirent_ftype);
	}
	/* CREATEINT: the dir ILOCK inside xfs_dir_lookup was the tag's
	 * one consumer; disarm immediately (iget below must not inherit it). */
	if (createint_armed) {
		mxfs_createint_exit(&createint_ent);
		createint_armed = false;
	}

	/*
	 * (instrumented, ungated, miss-only): the unlink_visibility loser's
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
			mxfs_probe("mxfs: P127-DIRMISS dp=%llu name=%.*s sfcount=%u names=[%s] size=%lld stale=%d gen=%u loaded_gen=%u dlm_mode=%u evgen=%u realns=%llu\n",
				(unsigned long long)dp->i_ino,
				name->len, (const char *)name->name,
				sfh->count, names,
				(long long)dp->i_disk_size, dp->i_dlm_stale,
				dp->i_dlm_dir_gen, dp->i_dlm_dir_loaded_gen,
				dp->i_dlm_mode, dp->i_dlm_dir_evicted_gen,
				(unsigned long long)ktime_get_real_ns());
		} else {
			mxfs_probe("mxfs: P127-DIRMISS dp=%llu name=%.*s fmt=%u (NOT-LOCAL) size=%lld stale=%d gen=%u loaded_gen=%u dlm_mode=%u evgen=%u realns=%llu\n",
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
	 * DIR-MISS discriminator (instr-gated): on a multi-node lookup
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
		mxfs_probe_ratelimited("mxfs: DIR-MISS name=%.*s dp_ino=%llu incore_dirsize=%lld disk_dirsize=%lld stale=%d fmt=%u (disk>incore=>STALE-DIR; equal=>NOT-DURABLE)\n",
			name->len, (const char *)name->name,
			(unsigned long long)dp->i_ino,
			(long long)dp->i_disk_size, (long long)ddsz,
			dp->i_dlm_stale, dp->i_df.if_format);
	  } }
	/*
	 * a lookup-miss retry under the dir ILOCK_SHARED was tried here
	 * to fix dirent-visibility (peer's freshly-created name invisible) but
	 * did NOT help (5-run 3/5, == baseline) — the miss is durable-before-
	 * visible (the peer's dirent isn't flushed to the medium when we read,
	 * and the dir-DLM acquire fast-paths / the BAST-flush chain races), not a
	 * stale-cache the acquire can refresh.  Reverted (it also added a dir-DLM
	 * acquire to every ENOENT path).  The real fix is dir-block durable-
	 * before-visible on dir-DLM release.
	 */
	{
		/* P-LOOKUP (gated): correlate EEXIST-loser stat->ENOENT
		 * with parent staleness/format.  rc=-2 (ENOENT) on a name a
		 * peer just created => stale parent on this node. */
		extern int mxfs_instr_enabled;
		if (unlikely(mxfs_instr_enabled) && dp->i_mount->m_mxfs_dlm)
			mxfs_probe("mxfs: P-LOOKUP dp_ino=%llu name=%.*s rc=%d inum=%llu dp_stale=%d dp_fmt=%u dp_size=%lld\n",
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
		/* FIX-B: a dirent-resolved inum that igets
		 * -ENOENT on a multi-node mount is (r11-proven) usually a
		 * sticky-stale CACHED inode-cluster buffer serving the old
		 * FREE image — peers iget the same inum fine.  Invalidate the
		 * cluster buf and retry (bounded); see
		 * mxfs_dlm_iget_miss_reload.
		 *
		 * FIX-D: when the invalidate can't act (no cached buf,
		 * or the failure is a dead in-core shell / not-yet-published
		 * fresh create), NUDGE: PR-acquire the ino's DLM by number —
		 * BASTs the creator into publishing (iflush + mirror) — then
		 * retry.  Bounded ~360ms worst-case on a genuinely dangling
		 * dirent; converges in ~1-2 tries on the create-race (the
		 * creator's drain is ~7ms).  See the helper's proof comment. */
		if ((error == -ENOENT || error == -EFSCORRUPTED) &&
		    igetmiss_tries < (mxfs_icluster_dlm ? 24 : 8)) {
			/* ICLUSTER: the 8-lap
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

			/* FIX-D v2: dead-shell reload first (the
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
				/* ICLUSTER (16-node
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
			/* daf50d34 acted==2 = a LOCAL mid-teardown
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
		/* the dir lookup SUCCEEDED (found the
		 * dirent + inum) but the iget FAILED — the dirent references a
		 * stale/freed inode (the dir_reuse_coherency lookup_fail residual
		 * with rebuild OFF: leaf/data find the name, iget -ENOENT because
		 * the on-disk inode is free).  Capture inum+err so a cross-node
		 * timeline shows whether the dirent points to a freed prior-
		 * incarnation inode (stale dir DATA block) vs an undurable alloc. */
		if (dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
			/* detection-triggered P172-WRTR ring dump
			 * (hard-throttled inside; see pal/linux/xfs_buf.c) */
			extern void mxfs_wrtr_dump_auto(void);

			mxfs_probe_ratelimited("mxfs: P26-IGET-FAIL dp=%llu name=\"%.*s\" inum=%llu err=%d ftype=%u\n",
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
	 * (D-0941): synthetic poison injection, default OFF.  See the
	 * mxfs_dbg_poison_nth definition for why the trigger is synthetic and
	 * the response is not.  Placed here so the injected flag is seen by the
	 * retirement arm below in THIS lookup, which is the code under test.
	 */
	if (unlikely(mxfs_dbg_poison_nth > 0) && *ipp &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    !xfs_iflags_test(*ipp, MXFS_IF_INCARN_STALE) &&
	    /*
	     * NO LOCAL PROVENANCE.  The revocation this poison queues calls
	     * truncate_inode_pages(), and every REAL poison site can afford
	     * that because it only fires when di_gen DIFFERS -- the number was
	     * freed and reused, so the pages belong to a dead incarnation and
	     * discarding them is correct.  An injector that poisons arbitrary
	     * LIVE inodes has no such licence: the first version of this hook
	     * threw away dirty pages of files the test had just written, and
	     * the row failed 'rv content node2_after_4(exp=content_2_4 got=)'
	     * -- a file reading EMPTY, which is nothing to do with the defect
	     * under test and everything to do with the harness.  A verification
	     * harness that manufactures its own distinct failure cannot verify
	     * anything, so the injector holds to the same precondition the code
	     * it exercises relies on.
	     */
	    atomic_read(&(*ipp)->i_pincount) == 0 &&
	    (*ipp)->i_delayed_blks == 0 &&
	    (!(*ipp)->i_itemp ||
	     (!(*ipp)->i_itemp->ili_fields &&
	      !test_bit(XFS_LI_IN_AIL,
			&(*ipp)->i_itemp->ili_item.li_flags))) &&
	    (!VFS_I(*ipp)->i_mapping ||
	     (!mapping_tagged(VFS_I(*ipp)->i_mapping, PAGECACHE_TAG_DIRTY) &&
	      !mapping_tagged(VFS_I(*ipp)->i_mapping,
			      PAGECACHE_TAG_WRITEBACK)))) {
		static atomic_t pnth = ATOMIC_INIT(0);

		if (atomic_inc_return(&pnth) % mxfs_dbg_poison_nth == 0) {
			pr_warn("mxfs: P566-POISON-INJECT ino=%llu name=%.*s — synthetic poison (dbg_poison_nth); retirement must still return the live incarnation\n",
				(unsigned long long)(*ipp)->i_ino,
				name->len, (const char *)name->name);
			mxfs_incarn_poison(*ipp);
		}
	}

	/*
	 * VFS staleness trap (design review design Part 2).
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
	 *  (Phase A): a POISONED shell needs no disk
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
	    dp->i_mount->m_mxfs_dlm) {
		struct inode	*vi = VFS_I(*ipp);

		/*
		 * (D-0941) ROOT FIX, instrument step 2b -- THE RETIRE LOOP
		 * WAS RACING A HELPER IT QUEUED ITSELF, AND LOSING BY THREE
		 * ORDERS OF MAGNITUDE.
		 *
		 * mxfs_incarn_poison() -- the call that sets the very flag this
		 * arm is reacting to -- takes an igrab() and hands it to
		 * mxfs_incarn_revoke_work_fn on the inode BAST workqueue.  That
		 * work is what zaps the dead incarnation's mappings and then
		 * drops the reference.  So from the instant the shell is
		 * poisoned there are exactly TWO references: ours, and the
		 * pending revocation's.  Retirement cannot succeed until that
		 * work has run.
		 *
		 * The old budget was four back-to-back iterations with NO delay
		 * of any kind.  Measured on the failing lap: the four tries
		 * spanned 23 MICROSECONDS end to end, while poison-to-revocation
		 * took 2.88 ms at best, 3.75 ms median and 68.4 ms at worst
		 * across ten inodes -- 125x the entire budget even in the
		 * fastest case.  Every one of those ten poisoned shells failed
		 * retirement and returned -ESTALE for a file that existed and
		 * whose dirent resolved correctly.  This was not an unlucky
		 * race; the loop could not win it.
		 *
		 * The revocation always runs and always drops its reference
		 * (10 of 10 in that capture), so the shell reliably BECOMES
		 * retireable -- waiting is not a gamble, it is the ordinary
		 * completion of an operation already in flight.  Retry with an
		 * escalating sleep, first try immediate because the work may
		 * already have run, then 2/4/8/16/32/64/128 ms: ~254 ms total,
		 * roughly 3.7x the worst latency measured.  The fail-closed
		 * -ESTALE below is unchanged and still guards the case where
		 * the reference genuinely never drops (an open fd on the dead
		 * incarnation), which is a different situation and must not be
		 * papered over by a longer wait.
		 *
		 * Cost is paid only on a poisoned shell, which requires a
		 * cross-incarnation reload; a healthy lookup never enters here.
		 */
		/*
		 * poison_retire_wait is THREE-valued, because two
		 * separate fixes live on this path and a two-valued knob cannot
		 * exercise the second one.
		 *
		 *   0  pre-fix control: 4 back-to-back tries, no sleep, and no
		 *      drain-assisted retirement.  Reproduces the defect.
		 *   1  SHIPPING DEFAULT: both fixes.  8 tries with an escalating
		 *      sleep, plus drain-assisted retirement behind it.
		 *   2  the escalating sleep OFF, drain-assisted retirement ON.
		 *
		 * Mode 2 exists for one reason.  Measured across eight injected
		 * node-laps in mode 1, P566-POISON-DRAINWAIT fired ZERO times:
		 * the escalating sleep retired every shell inside the try budget,
		 * so the budget never ran out and the drain path was never
		 * entered.  A clean mode-1 arm therefore verifies the FIRST fix
		 * and says nothing whatever about the second.  Mode 2 lets the
		 * short budget expire the way it does in the control, which is
		 * what puts the drain-assisted retirement under test.
		 */
		if (poison_tries++ <
		    (mxfs_poison_retire_wait == 1 ? 8 : 4)) {
			if (mxfs_poison_retire_wait == 1 && poison_tries > 1)
				msleep(1 << (poison_tries - 1));
			/*
			 *  (proven by instrument, design-consult ruling):
			 * prune+irele alone NEVER retired the shell — hashed,
			 * nlink>0, clean, so inode_generic_drop kept it cached at
			 * iput_final and retry_iget cache-hit it forever
			 * (P-EVICT-RESULT inew=0 tries=6, zsl .512 silent loss).
			 * d_mark_dontcache sets I_DONTCACHE so the LAST iput
			 * evicts even though hashed (a racing cache hit merely
			 * defers that to its own iput — the flag survives a
			 * non-reclaim hit, which is what we want).  Also revoke
			 * the page cache NOW: cached folios of the dead
			 * incarnation must not be mappable via map_pages once
			 * the shell lingers (invalidate_inode_pages2 also unmaps;
			 * the shell is clean by construction — the poison site
			 * only fires with no local provenance — so nothing can
			 * write back through the stale bmap).
			 */
			/*
			 * (D-0941, instrument step 2): i_count is a
			 * persistent 2 across every try while P34H-POISON-ALIAS
			 * prints nothing — so no dentry pins the shell and the
			 * one reference besides our own iget is unidentified.
			 * Everything that can hold it leaves a mark on the
			 * inode: a reclaim/inactivation in progress, an
			 * un-flushed log item, a pin, or a DLM grant this node
			 * still holds.  Print all of them at the moment the
			 * retire is attempted, so the holder is named rather
			 * than inferred from what happens to be in the log
			 * nearby.
			 */
			pr_warn_ratelimited(
				"mxfs: P34H-POISON-EVICT ino=%llu gen=%u try=%d i_count=%d i_state=0x%lx nlink=%u iflags=0x%lx pin=%d ili=0x%x in_ail=%d dlm_mode=%u reclaimable=%d need_inact=%d inactivating=%d iflushing=%d — retiring poisoned shell for re-iget\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, poison_tries,
				atomic_read(&vi->i_count), mxfs_istate(vi),
				vi->i_nlink,
				(*ipp)->i_flags,
				atomic_read(&(*ipp)->i_pincount),
				(*ipp)->i_itemp ? (*ipp)->i_itemp->ili_fields : 0,
				(*ipp)->i_itemp ?
					!!test_bit(XFS_LI_IN_AIL,
						   &(*ipp)->i_itemp->ili_item.li_flags) : 0,
				(*ipp)->i_dlm_mode,
				!!xfs_iflags_test(*ipp, XFS_IRECLAIMABLE),
				!!xfs_iflags_test(*ipp, XFS_NEED_INACTIVE),
				!!xfs_iflags_test(*ipp, XFS_INACTIVATING),
				!!xfs_iflags_test(*ipp, XFS_IFLUSHING));
			(*ipp)->i_dlm_stale = true; (*ipp)->i_dlm_stale_src = 15;
			d_mark_dontcache(vi);
			/*
			 * (D-0346, instrument step 2): name what pins the
			 * shell.  d_prune_aliases drops only UNUSED aliases; a
			 * directory alias whose cached children (the previous
			 * incarnation's entries) still reference it keeps its
			 * d_count > 0 and its inode reference, so i_count never
			 * reaches the last iput and every retry cache-hits the
			 * same dead shell.
			 */
			{
				struct dentry *al;

				spin_lock(&vi->i_lock);
				hlist_for_each_entry(al, &vi->i_dentry, d_u.d_alias)
					pr_warn_ratelimited(
						"mxfs: P34H-POISON-ALIAS ino=%llu dentry=%pd d_count=%u children=%d d_flags=0x%x\n",
						(unsigned long long)(*ipp)->i_ino, al,
						d_count(al),
						hlist_empty(&al->d_children) ? 0 : 1,
						al->d_flags);
				spin_unlock(&vi->i_lock);
			}
			d_prune_aliases(vi);
			if (S_ISREG(vi->i_mode))
				invalidate_inode_pages2(vi->i_mapping);
			xfs_irele(*ipp);
			*ipp = NULL;
			goto retry_iget;
		}
		/*
		 * FAIL CLOSED (design-consult: "a retry budget must never become
		 * a safety budget after which stale data is allowed").  The old
		 * fallthrough handed the poisoned shell to the VFS after 4 tries
		 * and file reads served the stale bmap.  There is no correct
		 * inode to return; -ESTALE is the revalidate-and-retry contract
		 * (same shape as the P201 typeflip-unresolved exit below).
		 */
		/*
		 * (D-0941, instrument step 2): DOES THE REFERENCE EVER
		 * DRAIN?  The four tries above run back to back with no delay
		 * at all — measured at 23 microseconds end to end — so a holder
		 * that would release in a millisecond defeats the budget every
		 * time, and "retirement failed" cannot presently distinguish a
		 * permanently-pinned corpse from a transient reference we never
		 * gave a chance to drop.  Sample i_count over a bounded wait and
		 * report the trajectory.  This does NOT change the outcome: the
		 * lookup still fails ESTALE below exactly as before.  It only
		 * runs on a path that is already failing, so it costs nothing in
		 * the healthy case, and it decides the fix — a reference that
		 * drains says "wait, bounded", one that never does says "find
		 * and release the holder".
		 *
		 * (D-0941, SECOND CAUSE — THE ANSWER THE PROBE ABOVE
		 * RETURNED, AND IT IS NOT THE FIRST CAUSE).  With the escalating
		 * wait in place the injected A/B still left ONE shell unretired
		 * in eight node-laps, and its give-up line reads:
		 *
		 *   P566-POISON-DRAINWAIT ino=8388742 i_count_first=3
		 *       i_count_after=1 drained_at_ms=10
		 *   P34H-POISON-UNRETIRED ino=8388742 i_count=1 tries=9
		 *
		 * i_count=1 is OUR OWN reference and nothing else: the shell was
		 * retireable at the very moment the code declared it unretireable
		 * and failed the lookup.  The holder was not the poison's own
		 * revocation this time — the reference ring names
		 * mxfs_dlm_bast_work_fn and mxfs_dlm_bast_dwork_fn, the DLM BAST
		 * pipeline, taking a transient reference that pushed i_count back
		 * from 2 to 3 at try 8 and dropped it 10 ms later.  So the budget
		 * was not too short for the holder we knew about; it was spent by
		 * a DIFFERENT, unrelated holder arriving late.
		 *
		 * A fixed try count cannot be the exit condition when references
		 * arrive from paths this loop does not control.  The exit
		 * condition that IS correct is the one this block already
		 * measures: the reference is gone.  So when the wait observes it
		 * go, retire on that observation instead of discarding it —
		 * bounded by poison_drains, so a genuinely pinned corpse still
		 * fails closed exactly as before rather than looping.
		 */
		{
			int	pc_first = atomic_read(&vi->i_count);
			int	pc_now = pc_first;
			int	waited_ms = 0;
			int	drained_at = -1;

			while (waited_ms < 200) {
				msleep(5);
				waited_ms += 5;
				pc_now = atomic_read(&vi->i_count);
				if (pc_now <= 1) {	/* only our own ref left */
					drained_at = waited_ms;
					break;
				}
			}
			pr_warn(
				"mxfs: P566-POISON-DRAINWAIT ino=%llu gen=%u i_count_first=%d i_count_after=%d drained_at_ms=%d waited_ms=%d iflags=0x%lx pin=%d ili=0x%x dlm_mode=%u i_state=0x%lx name=%.*s\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, pc_first, pc_now,
				drained_at, waited_ms,
				(*ipp)->i_flags,
				atomic_read(&(*ipp)->i_pincount),
				(*ipp)->i_itemp ? (*ipp)->i_itemp->ili_fields : 0,
				(*ipp)->i_dlm_mode, mxfs_istate(vi),
				name->len, (const char *)name->name);

			/*
			 * The reference we were waiting for is gone.  Act on
			 * that rather than on the exhausted try counter.
			 *
			 * GATED ON THE SAME KNOB AS THE WAIT, AND THAT IS NOT
			 * COSMETIC.  poison_retire_wait exists so the defect and
			 * the fix can be measured against each other in ONE
			 * build and ONE boot.  The first version of this block
			 * ran unconditionally, which silently turned the control
			 * arm into a second treatment arm: on 0.75.106 the
			 * retire_wait=0 arm reported unretired=0 lkerr116=0
			 * where the same arm on 0.75.105 had tracked poison_n
			 * 1:1.  The fix was working -- and the A/B had stopped
			 * being an A/B, which is the vacuity failure this defect
			 * has already been caught by twice.  Anything that
			 * changes the outcome belongs behind the knob.
			 */
			if (mxfs_poison_retire_wait != 0 &&
			    drained_at >= 0 && poison_drains++ < 2) {
				pr_warn(
					"mxfs: P567-POISON-DRAINRETIRE ino=%llu gen=%u drained_at_ms=%d drain=%d tries=%d name=%.*s — reference drained after the try budget; retiring on the observation instead of failing the lookup\n",
					(unsigned long long)(*ipp)->i_ino,
					vi->i_generation, drained_at,
					poison_drains, poison_tries,
					name->len, (const char *)name->name);
				(*ipp)->i_dlm_stale = true;
				(*ipp)->i_dlm_stale_src = 15;
				d_mark_dontcache(vi);
				d_prune_aliases(vi);
				if (S_ISREG(vi->i_mode))
					invalidate_inode_pages2(vi->i_mapping);
				xfs_irele(*ipp);
				*ipp = NULL;
				goto retry_iget;
			}
		}
		/*
		 * (D-0941): NAME THE HOLDER.  Every reference this
		 * filesystem takes goes through mxfs_igrab_tracked / the
		 * tracked iput, which record the call site into a per-inode
		 * event ring and an outstanding-grab stack scoped to the
		 * current tenure.  That machinery already exists for the
		 * unmount-busy-inode probe; nothing was consulting it here, so
		 * "retirement failed" named the symptom and not the cause.
		 * With i_count==2 and an empty dentry alias list, the
		 * outstanding-grab stack holds the answer directly.
		 */
		{
			int	k;

			for (k = 0; k < MXFS_GRABST_N; k++) {
				unsigned long	who = (*ipp)->i_mxfs_grabst[k];

				if (!who)
					continue;
				if ((*ipp)->i_mxfs_grabst_kind[k] == 2)
					mxfs_probe("mxfs:   P566-GRABST[%d] ino=%llu site=file%lu:line%lu\n",
						k, (unsigned long long)(*ipp)->i_ino,
						who >> 32, who & 0xffffffffUL);
				else
					mxfs_probe("mxfs:   P566-GRABST[%d] ino=%llu %pS\n",
						k, (unsigned long long)(*ipp)->i_ino,
						(void *)who);
			}
			for (k = 0; k < MXFS_REFEV_N; k++) {
				int		idx = ((*ipp)->i_mxfs_refev_head + k) %
							MXFS_REFEV_N;
				unsigned long	who = (*ipp)->i_mxfs_refev_ip[idx];
				unsigned char	kind = (*ipp)->i_mxfs_refev_kind[idx];

				if (!who)
					continue;
				if (kind >= 2)
					mxfs_probe("mxfs:   P566-REFEV[%d] ino=%llu %s site=file%lu:line%lu count_after=%u\n",
						k, (unsigned long long)(*ipp)->i_ino,
						kind == 2 ? "GRAB" : "RELE",
						who >> 32, who & 0xffffffffUL,
						(*ipp)->i_mxfs_refev_cnt[idx]);
				else
					mxfs_probe("mxfs:   P566-REFEV[%d] ino=%llu %s %pS count_after=%u\n",
						k, (unsigned long long)(*ipp)->i_ino,
						kind == 1 ? "IGET" : "IRELE",
						(void *)who,
						(*ipp)->i_mxfs_refev_cnt[idx]);
			}
			mxfs_probe("mxfs:   P566-GRABST-SUMMARY ino=%llu tenure_grabs=%u over=%u tgrabs=%u tputs=%u last_grab=file%u:line%u\n",
				(unsigned long long)(*ipp)->i_ino,
				(*ipp)->i_mxfs_tenure_grabs,
				(*ipp)->i_mxfs_grabst_over,
				(*ipp)->i_mxfs_tgrabs, (*ipp)->i_mxfs_tputs,
				(*ipp)->i_mxfs_grab_file, (*ipp)->i_mxfs_grab_line);
		}
		pr_warn(
			"mxfs: P34H-POISON-UNRETIRED ino=%llu gen=%u i_count=%d i_state=0x%lx tries=%d name=%.*s — retirement failed; failing lookup -ESTALE rather than serving a dead incarnation\n",
			(unsigned long long)(*ipp)->i_ino,
			vi->i_generation, atomic_read(&vi->i_count),
			mxfs_istate(vi), poison_tries,
			name->len, (const char *)name->name);
		xfs_irele(*ipp);
		*ipp = NULL;
		error = -ESTALE;
		goto out_free_name;
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
		 * ROOT FIX (PROVEN by P91-STALEFLAG-DISK): the INODE_FREE
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
		/*
		 * 0.84.24 (a peer's mkdir under a directory the other node had
		 * just recreated answered ESTALE; 2 nodes / TCP, measured on the
		 * 2026-09-12 board at 22:19:53, ino 10594).  A slot that reads
		 * FREE here is not yet a verdict.  The name just resolved from a
		 * PUBLISHED parent, so a creator holds the number's new
		 * incarnation under a deferred-published EX whose dinode is
		 * still only logged: the platter shows the post-free image (mode
		 * 0, generation old+1), which is exactly what a genuinely freed
		 * slot shows too.  Measured, this arm read that image, spent its
		 * four evictions cache-hitting the same referenced shell, and
		 * returned the previous incarnation as an existing directory; the
		 * grant-less reload that followed then poisoned it, and the
		 * create was refused ESTALE.  The cache-MISS path answers the
		 * same window with one coordinated PR acquire (P127-IGET-COORD):
		 * the request reaches the master, BASTs the creator's published
		 * EX, and its release drain destages the new dinode before the
		 * grant; the acquire's own slow-path reload then adopts the live
		 * incarnation in place under that grant.  Do the same here, once
		 * per lookup, and re-read before deciding.  A number that is
		 * genuinely free gets an uncontended acquire and still reads
		 * free, and the arm below then behaves exactly as before.
		 */
		if (s91_dmode == 0 && !reuse_coord &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
			extern void mxfs_dlm_force_peer_flush(struct xfs_inode *);

			reuse_coord = 1;
			mxfs_probe_ratelimited(
				"mxfs: P346-REUSE-COORD ino=%llu gen=%u dgen=%u name=%.*s — dirent names a slot that reads free; one coordinated PR acquire so a creator's undrained new incarnation is destaged before this shell is judged\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, s91_dgen,
				name->len, (const char *)name->name);
			mxfs_dlm_force_peer_flush(*ipp);
			(void)mxfs_inode_disk_di_size(*ipp, &s91_dmode,
						      &s91_dgen);
			mxfs_probe_ratelimited(
				"mxfs: P346-REUSE-COORD-READ ino=%llu incore_gen=%u incore_mode=0%o dmode=0%o dgen=%u dlm_mode=%u stale=%d\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, vi->i_mode & 0xFFFF,
				s91_dmode, s91_dgen, (*ipp)->i_dlm_mode,
				(*ipp)->i_dlm_stale ? 1 : 0);
		}
		if (s91_dmode != 0 &&
		    s91_dmode == (VFS_I(*ipp)->i_mode & 0xFFFF) &&
		    s91_dgen == (uint32_t)VFS_I(*ipp)->i_generation) {
			mxfs_probe_ratelimited(
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
			 * FIX (review-confirmed, instrument step 2b): SAME-TYPE
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
			 * referenced inode is safe (the in-place-reload
			 * deadlock concern was specific to type-FLIP iops rewiring,
			 * which still goes through clean eviction below).  With
			 * fua_disable=1 this is the ONLY path that refreshes a
			 * referenced, gen-stale directory.
			 */
			mxfs_probe_ratelimited(
				"mxfs: P95-SAMETYPE-RELOAD ino=%llu incore_gen=%u disk_gen=%u dmode=0%o try=%d\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, s91_dgen, s91_dmode,
				evict_tries);

			/*
			 * ROOT FIX, same-type arm —
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
					mxfs_probe_ratelimited(
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
			mxfs_probe_ratelimited(
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
	 * mxfs: cross-node inode-number REUSE coherency (proven,
	 * acted on).
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
	 * inode deadlocks/races; eviction + clean re-instantiation
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

		mxfs_probe_ratelimited(
			"mxfs: INODE-REUSE-EVICT ino=%llu incore_ftype=%u dirent_ftype=%u name=%.*s try=%d\n",
			(unsigned long long)(*ipp)->i_ino,
			xfs_mode_to_ftype(VFS_I(*ipp)->i_mode),
			dirent_ftype, name->len, (const char *)name->name,
			evict_tries);

		/*
		 * FORCE the peer that created the new incarnation to
		 * flush its dinode NOW, rather than waiting (up to a 120s barrier
		 * timeout) for its lazy iflush.  A PR acquire BASTs the creator's
		 * sticky-cached EX grant -> it drains+iflushes the new dinode
		 * before downconverting, so the gen-gated recycle re-read below
		 * sees the fresh incarnation on the NEXT iget instead of looping
		 * 4x on the stale disk image.  i_dlm_stale is still clear here, so
		 * this does NOT trigger an in-place reload of the wrong-type stale
		 * inode (which deadlocks —); we use only the BAST/flush
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
	 * FIX2 (review-confirmed, instrument step 2b): TYPE-FLIP reuse where
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
	 * rewires i_op/i_fop on an S_IFMT change (/90 P-RELOAD-IOPS-
	 * REWIRE) and only ADOPTS a strictly-newer disk_gen type-flip (genuine
	 * reuse; the typeflip guard rejects stale/torn reads with disk_gen <=
	 * incore_gen).  It uses down_write_trylock + bail (no deadlock — the
	 * in-place-reload concern was a plain down_write, since fixed),
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
	    /* "an eviction loop above was tried" now spans BOTH
	     * counters -- the poisoned-shell arm keeps its own retry budget,
	     * so gating on evict_tries alone would silently stop arming this
	     * resolver after a successful poison retirement. */
	    (evict_tries > 0 || poison_tries > 0) &&
	    dirent_ftype != XFS_DIR3_FT_UNKNOWN &&
	    dirent_ftype < XFS_DIR3_FT_MAX &&
	    VFS_I(*ipp)->i_mode != 0 &&
	    xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) != dirent_ftype) {
		/*
		 * ROOT FIX — cc uv lost-create /
		 * ENOTDIR window (instrumented, two live captures: 233839Z test16
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

		mxfs_probe_ratelimited(
			"mxfs: P95-TYPEFLIP-RELOAD ino=%llu incore_ftype=%u dirent_ftype=%u name=%.*s tries=%d\n",
			(unsigned long long)(*ipp)->i_ino,
			xfs_mode_to_ftype(VFS_I(*ipp)->i_mode),
			dirent_ftype, name->len, (const char *)name->name,
			evict_tries);

		/* BAST the creator to flush the fresh dinode, then reload it. */
		{ extern void mxfs_dlm_force_peer_flush(struct xfs_inode *);
		  mxfs_dlm_force_peer_flush(*ipp); }
		/*
		 *  — TEST-ONLY: force the resolver to give
		 * up immediately, so the P201 give-up path can be EXERCISED.
		 * Type flips are common (165 waits in one 32-node run) but the
		 * unresolved outcome is not reproducible on demand, and the zero-defect bar
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

			mxfs_probe_ratelimited(
				"mxfs: P95B-TYPEFLIP-WAIT ino=%llu resolved=%d rounds=%d final_ftype=%u dirent_ftype=%u name=%.*s\n",
				(unsigned long long)(*ipp)->i_ino,
				p95_ok ? 1 : 0,
				p95w,
				VFS_I(*ipp)->i_mode ?
					xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) : 0,
				dirent_ftype, name->len,
				(const char *)name->name);

			/*
			 *  — DO NOT PUBLISH A MISMATCHED
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
				 *  — WHICH SIDE IS ACTUALLY
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
				 *     reading);
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
					mxfs_probe("mxfs: P207-COHERENT-TRUTH ino=%llu coh_mode=0%o coh_gen=%u incore_mode=0%o incore_gen=%u dirent_ft=%u dlm_mode=%d dlm_state=%d name=%.*s\n",
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
					 * include the PARENT's coherency
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
					mxfs_probe("mxfs: P201-TYPEFLIP-UNRESOLVED-FAIL ino=%llu incore_ftype=%u dirent_ftype=%u incore_mode=0%o incore_gen=%u pino=%llu p_fmt=%d p_valid_epoch=%u p_dir_gen=%llu p_loaded_gen=%u p_stale=%d name=%.*s comm=%s — type flip UNRESOLVED after %d rounds; failing the lookup with -ESTALE rather than publishing a dirent/inode type mismatch\n",
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

	/* decisive — when we evicted at least once, log the FINAL
	 * inode the retry delivered.  If incore_ftype still != dirent_ftype
	 * the loop must have hit the try<4 cap (it didn't, only try=1 seen)
	 * or fell through; if it MATCHES yet userspace still sees a dir, the
	 * bug is in the dcache/dentry, not the inode. */
	if ((evict_tries > 0 || poison_tries > 0) && *ipp &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		struct inode *vi2 = VFS_I(*ipp);
		extern const struct file_operations xfs_dir_file_operations;
		mxfs_probe_ratelimited(
			"mxfs: P-EVICT-RESULT ino=%llu ip=%px final_mode=0%o final_ftype=%u dirent_ftype=%u gen=%u inew=%d fop_dir=%d tries=%d name=%.*s\n",
			(unsigned long long)(*ipp)->i_ino, *ipp,
			vi2->i_mode,
			vi2->i_mode ? xfs_mode_to_ftype(vi2->i_mode) : 0,
			dirent_ftype, vi2->i_generation,
			(inode_state_read_once(vi2) & I_NEW) ? 1 : 0,
			(vi2->i_fop == &xfs_dir_file_operations) ? 1 : 0,
			evict_tries + poison_tries,
			name->len, (const char *)name->name);
	}

	/*
	 * cross-node INODE-NUMBER REUSE coherency (dir<->file).
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
	 * cross-node inode-reuse (dir<->file) detection.  Detection is
	 * proven correct (INODE-REUSE-FIX fires with incore dir vs disk file),
	 * but doing the in-place reload+xfs_setup_iops HERE under ILOCK_EXCL
	 * DEADLOCKS (stat stuck in D-state) — reload's buffer I/O / DLM under
	 * the held lock during a path-walk lookup is unsafe.  The safe fix
	 * (drop the stale dentry aliases so the inode reclaims, then recycle-
	 * re-instantiate) is deferred; detection-only here for diagnosis.
	 */
	/*
	 * detection-only di_size probe for same-type reused-inode
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
				mxfs_probe_ratelimited("mxfs: INODE-REUSE-DETECT ino=%llu incore_gen=%u disk_gen=%u disk_size=%lld dlm_mode=%u name=%.*s\n",
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
	/* P-LKERR tripwire — see declaration comment.  Racy unlocked
	 * reads are fine for diagnostics; never blocks, never acquires. */
	if (unlikely(error && error != -ENOENT) && dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm))
		mxfs_probe_ratelimited(
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
	 * ROOT FIX for dir_reuse_coherency 2/tcp inode-revert:
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
	/* pin dp's DLM EX across the ILOCK-dropped create-durability flush
	 * (computed once at iunlock, reused at the durable call ~85 lines later). */
	bool			mxfs_create_dp_durable = false;
	uint			resblks;
	int			error;
	/* (instrumented): per-mkdir phase decomposition for the 16-node
	 * same-dir create-storm throughput blocker.  Always-on for DIR
	 * creates on multi-node mounts only (mkdir is rare outside the
	 * storm; ~80 lines per criterion run). */
	u64			p132_t0 = 0, p132_tpre = 0, p132_tcommit = 0;
	u64			p132_tdirsig = 0, p132_tpub = 0;
	/* the three sequential waits that pre_ms used to hide.  They
	 * are stamped at call boundaries inside this function, so they are
	 * mutually exclusive by construction -- a decomposition assembled from
	 * probes at separate depths can have several buckets claim one wait. */
	u64			p132_tres = 0, p132_tdlk = 0, p132_tdia = 0;
	/* the in-tenure create (dlk_ms ~1) still costs ~18 ms at 32
	 * nodes, 9.6 of them in the unattributed span between dialloc and the
	 * commit.  Four more stamps split that span at the MXFS hooks that do
	 * synchronous I/O: the modify refresh + adopt FUA read of the dir inode
	 * (rfr), lookup + icreate (icr), peer merge + stale reconcile + pending
	 * replay (mrg), and xfs_dir_create_child (cc). */
	u64			p132_trfr = 0, p132_ticr = 0, p132_tmrg = 0, p132_tcc = 0;
	/* (0.69.5): icr_ms measured 4.6 ms in the shared arm against 0.3
	 * in the private one (chain 137).  Split it at the lookup boundary so
	 * lkp_ms is the existence lookup on the (large, shared) directory and
	 * icr_ms is xfs_icreate alone — i.e. xfs_iget's inode-cluster buffer
	 * read plus the cluster-grant claim, the two candidates that differ
	 * between a shared and a private allocation group. */
	u64			p132_tlkp = 0;
	/* what the lookup term IS — node-wide synchronous FUA
	 * passthrough reads (count + wall) and plain read bios issued while
	 * the existence lookup ran.  Node-wide counters, so a concurrent
	 * reader on this node can inflate them; the row has one writer per
	 * node, so the attribution is tight enough to decide the hypothesis
	 * (lookup cost = cold directory-block reads after the tenure evict). */
	extern atomic64_t	mxfs_fua_read_calls, mxfs_fua_read_ns, mxfs_buf_read_bios;
	u64			p132_fua0 = 0, p132_fuans0 = 0, p132_rd0 = 0;
	u64			p132_lkp_fua = 0, p132_lkp_fua_ns = 0, p132_lkp_rd = 0;
	int			p132_thr = READ_ONCE(mxfs_create_cost_ms);

	trace_xfs_create(dp, name);
	/*
	 * stamped on every clustered create, not only when the P132
	 * line is armed.  The P483-DIRTENURE tenure wall below is derived from
	 * this clock, and the 0.69.3 board's 662 tenure lines all read
	 * wall_ms=0 because create_cost_ms was off — the probe that was built
	 * to be always-on had its only cost field gated on a second knob.  The
	 * P132 print itself stays gated (xfs_inode.c, the p132_thr test).
	 */
	if (mp->m_mxfs_dlm)
		p132_t0 = ktime_get_ns();

	/* H40: log ALL xfs_create entries with parent ino + name.
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

	/*  (Phase A): creating inside a POISONED dead
	 * dir incarnation forges parallel universes (the 140939Z corpse-dir
	 * round).  -ESTALE + prune so the path re-resolves the live parent.
	 * Entry context — no locks held yet. */
	if (mp->m_mxfs_dlm && xfs_iflags_test(dp, MXFS_IF_INCARN_STALE)) {
		d_prune_aliases(VFS_I(dp));
		return -ESTALE;
	}

	/*
	 * 0.75.47 lab knob: hold the create between the VFS lookup
	 * that found the name absent and the directory lock, so a peer
	 * creating the same name in the meantime wins and this create takes
	 * the loser branch below (D-0921 reproducer).  Off by default.
	 */
	if (mp->m_mxfs_dlm && !is_dir) {
		extern int mxfs_create_race_delay_ms;
		int race_delay = READ_ONCE(mxfs_create_race_delay_ms);

		if (unlikely(race_delay > 0))
			msleep(race_delay);
	}

	/* Make sure that we have allocated dquot(s) on disk. */
	error = xfs_icreate_dqalloc(args, &udqp, &gdqp, &pdqp);
	if (error)
		return error;

	if (is_dir) {
		resblks = xfs_mkdir_space_res(mp, name->len);
		tres = &M_RES(mp)->tr_mkdir;
		/*
		 * when forcing new multinode dirs to block format
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
	 * reserve block headroom for the in-transaction block-dir peer
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

	/* headroom for pending-dirent replay (re-add our own dirents a
	 * stale-block0 adopt dropped — the dir_reuse node1_f1 fix).  Bounded to
	 * MXFS_PEND_REPLAY_MAX extra inserts; multi-node dir creates only. */
	if (!is_dir && mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		resblks += MXFS_PEND_REPLAY_MAX *
			   XFS_DIRENTER_SPACE_RES(mp, MAXNAMELEN - 1);

	error = xfs_parent_start(mp, &du.ppargs);
	if (error)
		goto out_release_dquots;

	/*
	 * (MODE B fix): adopt a peer-stale SHORTFORM parent-dir base
	 * BEFORE taking dp ILOCK_EXCL, so the create's existence-check + dirent
	 * add RMW the peer's durable image (not a stale inline-dirent base that
	 * would resurrect a peer's removed entries).  No-op once ILOCK is held.
	 */
	mxfs_dlm_dir_modify_reload_prelock(dp);

	/*
	 * the pre-lock block-dir merge (mxfs_dir_merge_peer_blocks)
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
	/* log-space grant wait lands here -- xfs_trans_alloc_icreate
	 * blocks in xlog_grant_head_wait when the log is full. */
	if (p132_t0)
		p132_tres = ktime_get_ns();

	/*
	 * v0.3.148 do NOT hold dp ILOCK across xfs_dialloc.
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
	 * nodes wedge.  P67-INSTR captured this exactly:
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
	 * PROVEN BY INSTRUMENT cross-node ABBA (fence suite-3
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
	 * BOTH transes dirty, so neither the P5D clean-trans breaker
	 * nor the deferred-BAST honor could yield.  t3 repeated it 68s
	 * later; netpartition + tcp_dlm_scaling inherited dead FSes.
	 *
	 * Fix the ORDER, not the symptom: take dp's DLM EX BEFORE
	 * xfs_dialloc and keep the GRANT (not the rwsem) pinned across the
	 * alloc, so every dirtying path agrees on dir -> AG.  The v0.3.148
	 * rwsem drop is preserved verbatim (peer xfsaild iop_push trylocks
	 * the rwsem, not the DLM pin), so the AIL mirror-wedge
	 * cannot return.  A peer wanting the dir now simply waits out this
	 * create's bounded tenure (BASTs defer against i_dlm_pin_count;
	 * mxfs_inode_unpin at the re-lock hands deferral to the Approach-A
	 * trans hook), instead of entering an unbreakable dirty-dirty cycle.
	 */
	/*
	 * 0.84.11 (D-0958): this first acquire of the parent is a FALLIBLE
	 * boundary.  Nothing is dirty here: xfs_trans_alloc_icreate has only
	 * reserved log space and quota, no inode has been allocated, nothing
	 * is joined, and the pre-lock reload above took no lock.  When the
	 * cluster grant under it is abandoned — a live master never
	 * acknowledged the request past the budget, or this task was killed —
	 * the create fails with that errno holding nothing, cancelling the
	 * clean reservation through the same unwind the quarantine backstop
	 * below takes, instead of restarting the wait for ever.  Measured
	 * before this (s594d shape, on the directory): a create whose EX
	 * request was discarded at the sender parked in this acquire past
	 * every budget while the master stayed a healthy member.
	 */
	if (mp->m_mxfs_dlm) {
		error = mxfs_ilock_fallible(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
		if (unlikely(error)) {
			ino = 0;		/* P-CR3-CANCEL prints it */
			mxfs_namespace_refused(dp, is_dir ? "mkdir" : "create",
					       error);
			goto out_trans_cancel;
		}
	} else {
		xfs_ilock(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
	}
	/* this xfs_ilock carries the parent directory's cross-node DLM
	 * EX acquire, so dlk_ms is the shared-directory queue wait -- the term
	 * P291-EXWIN measures from the DLM side. */
	if (p132_t0)
		p132_tdlk = ktime_get_ns();
	/* D-0515 backstop: the dir's DLM acquire may have been REFUSED
	 * (quarantined victim domain).  The transaction is still clean here —
	 * xfs_dialloc below is what dirties it — so this is the last point a
	 * refused acquire can be turned into a clean failure. */
	error = mxfs_quar_gate_locked(dp, "create");
	if (unlikely(error)) {
		ino = 0;			/* P-CR3-CANCEL prints it */
		xfs_iunlock(dp, XFS_ILOCK_EXCL);
		goto out_trans_cancel;
	}
	mxfs_inode_pin(dp);
	xfs_iunlock(dp, XFS_ILOCK_EXCL);
	error = xfs_dialloc(&tp, args, &ino);
	/* dialloc carries the AG DLM acquire (inode allocation picks an
	 * AG by affinity, then takes that AG's grant), so dia_ms is the AG
	 * contention term -- the one D-RSYNC-LAP-PACE-AG-SHARING-388 predicts
	 * will separate nodes with an exclusive AG from nodes that collide. */
	if (p132_t0)
		p132_tdia = ktime_get_ns();
	/* sess-tcp (instrumented): split dialloc vs icreate as the err=1/ino=0 source
	 * on the first multi-node create.  Fires only when dialloc misbehaves. */
	if (unlikely(error || ino == 0 || ino == NULLFSINO))
		mxfs_probe("mxfs: P-DIALLOC dp=%llu err=%d ino=%llu single=%d\n",
			(unsigned long long)dp->i_ino, error,
			(unsigned long long)ino,
			mp->m_mxfs_dlm ? mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) : -1);
	if (!error) {
		xfs_ilock(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
		/* dialloc window over — the rwsem hold resumes BAST
		 * deferral duty (Approach-A / holder gates); drop the pin. */
		mxfs_inode_unpin(dp);
		unlock_dp_on_error = true;

		/*
		 * sess-pve DEBUG fault injection (default off).  xfs_dialloc above
		 * logged + mxfs_ag_meta_track'd the AGI/inobt/finobt for this AG, so
		 * the transaction is now dirty with tracked AG-meta buffers.  Force a
		 * DIRTY xfs_trans_cancel here — the exact signature of the natural
		 * stale-inode dialloc corruption — so the AGI umount-wedge
		 * shutdown-abort reclaim (mxfs_ag_meta_reclaim) fires
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
		 * MODIFY-side acquire cold-read for create (mirror of the
		 * xfs_remove/xfs_rename fix).  dp ILOCK_EXCL is held.  Drop our
		 * stale cached dir DATA blocks if a peer modified dp since our last
		 * refresh, so BOTH the EEXIST re-validate below AND the eventual
		 * xfs_dir_create_child RMW read the peer's DURABLE committed image.
		 * Without this, adding our new dirent from a stale base clobbers a
		 * peer's already-committed dirents (durable lost-update).
		 */
		mxfs_dlm_dir_modify_refresh(dp);

		/*
		 * mxfs_dir_modify_adopt_disk_format was REFUTED — the
		 * staleness is CONTENT-level in the dir DATA buffer (dirty bufgen=0
		 * block0 materialized on a stale base), NOT the inode fork
		 * format/nextents/size (which is never behind disk under EX).  The
		 * format/count compare never fires.  Call DISABLED; the real fix is
		 * a tenure-cookie invariant at block0 materialization (design review case A) or
		 * a DLM double-grant fix (case B) — verify A/B first.  See ccmemory
		 * docs/history/decisive-dirty-bufgen0-divergent-block0-kept-by-dirty-guard.md.
		 */
		/* mxfs_dir_modify_adopt_disk_format REFUTED AGAIN (at the
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
			mxfs_probe("mxfs: P62-CRCONV dp=%llu incore_fmt=%d dlm_mode=%u gen=%u name=\"%.*s\" comm=%s\n",
				(unsigned long long)dp->i_ino,
				dp->i_df.if_format, dp->i_dlm_mode,
				VFS_I(dp)->i_generation,
				name->len, name->name, current->comm);
		/*
		 *  RE-ENABLED.  mxfs_dir_modify_adopt_disk_format
		 * (xfs_mxfs_dlm.c) now ALSO catches the LOCAL/LOCAL content-level gap
		 * identified but never closed (di_size growth compared on the
		 * SAME FUA read the format check already does -- no extra I/O beyond
		 * the read itself).  Gate the read on i_dlm_dir_gen>0 (a peer has
		 * touched this dir since we last synced, bumped by the async
		 * DIR_MODIFY evict-ring notification independent of our own EX
		 * acquire) so a node-private / never-shared dir never pays the FUA
		 * cost -- bounds this to exactly the dirs that need it, addressing
		 * the budget rule perf objection to the unconditional call.
		 */
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    dp->i_dlm_dir_gen > 0)
			mxfs_dir_modify_adopt_disk_format(dp,
					XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
		if (p132_t0)
			p132_trfr = ktime_get_ns();

		/* (instrumented): PROVE the directory-inode divergence.  The
		 * rename_visibility loser's before-files are NEVER created into the
		 * live shared dir block (its mv then fails "No such file").  Log the
		 * PARENT dir inode each create targets so a cross-node merge shows
		 * whether the loser creates into a DIFFERENT (orphaned/stale) parent
		 * inode than its peers for the same path (concurrent-mkdir / stale
		 * dentry divergence). run14d: gated mxfs.dirwr/
		 * mxfs.instr for ship (fires per multi-node create). */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
			mxfs_probe_ratelimited(
				"mxfs: P105-CREATE-PARENT dp=%llu name=\"%.*s\" realns=%llu\n",
				(unsigned long long)dp->i_ino,
				name->len, name->name,
				(unsigned long long)ktime_get_real_ns());

		/*
		 * MXFS Mode A fix (robust): re-validate non-existence of
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

			if (p132_t0) {
				extern int mxfs_lkp_trace, mxfs_lkp_trace_open;

				p132_fua0 = atomic64_read(&mxfs_fua_read_calls);
				p132_fuans0 = atomic64_read(&mxfs_fua_read_ns);
				p132_rd0 = atomic64_read(&mxfs_buf_read_bios);
				/* open the node-wide read trace for this
				 * lookup (P495-LKP-RD); the sampled create is the
				 * only creator on the node in the cc row, so the
				 * window attributes every read to its task. */
				if (unlikely(mxfs_lkp_trace)) {
					mxfs_probe("mxfs: P495-LKP-WIN open parent=%llu pid=%d comm=%s\n",
						(unsigned long long)dp->i_ino,
						current->pid, current->comm);
					WRITE_ONCE(mxfs_lkp_trace_open, 1);
				}
			}
			lrc = xfs_dir_lookup_locked(tp, dp, name, &existing_ino);
			if (p132_t0) {
				extern int mxfs_lkp_trace_open;

				if (READ_ONCE(mxfs_lkp_trace_open)) {
					WRITE_ONCE(mxfs_lkp_trace_open, 0);
					mxfs_probe("mxfs: P495-LKP-WIN close parent=%llu lrc=%d pid=%d\n",
						(unsigned long long)dp->i_ino, lrc,
						current->pid);
				}
				p132_tlkp = ktime_get_ns();
				p132_lkp_fua = atomic64_read(&mxfs_fua_read_calls) - p132_fua0;
				p132_lkp_fua_ns = atomic64_read(&mxfs_fua_read_ns) - p132_fuans0;
				p132_lkp_rd = atomic64_read(&mxfs_buf_read_bios) - p132_rd0;
			}
			/* (instrumented): PROVE the directory-inode divergence.
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
				mxfs_probe("mxfs: P106-MKDIR parent=%llu name=\"%.*s\" lookup_rc=%d existing_ino=%llu new_ino=%llu realns=%llu\n",
					(unsigned long long)dp->i_ino,
					name->len, name->name, lrc,
					(unsigned long long)(lrc == 0 ? existing_ino : 0),
					(unsigned long long)ino,
					(unsigned long long)ktime_get_real_ns());
			if (lrc == 0) {
				struct xfs_icreate_args orphan = *args;

				/*
				 * (PROVEN BY INSTRUMENT — corrects): do NOT set
				 * dp->i_dlm_stale here.  Phase-1 fix set it on the
				 * premise that the loser's cached parent dir doesn't reflect
				 * the winner's child — but that premise is FALSE.  To reach
				 * this branch we acquired dp ILOCK_EXCL just above, which
				 * forced the winner to release its dp lock and reloaded dp
				 * fresh FROM the durable peer-committed image: the reload
				 * (P-SFDIR-RELOAD) already shows the winner's child entry.
				 * The parent IS coherent.  Setting i_dlm_stale=true instead
				 * RE-INTRODUCED the stuck-stale d_revalidate thrash:
				 * PROVEN (dmesg) — d_revalidate(parent) then returned
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
				mxfs_probe("mxfs: P127-EEXIST-LOSER dp=%llu name=\"%.*s\" winner_ino=%llu dp_stale=%d dp_fmt=%d realns=%llu\n",
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
				/* mxfs: THIS node created this nlink==0
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
		if (p132_t0)
			p132_ticr = ktime_get_ns();
	}
	if (error) {
		/*
		 * If dialloc failed, we never re-acquired dp ILOCK above.
		 * out_trans_cancel still expects unlock_dp_on_error to be
		 * accurate; it remains false here, consistent with our
		 * not-holding state.
		 */
		/* balance the pre-dialloc dir-DLM pin.  Only when the
		 * re-lock (which unpins on the success path) never ran —
		 * unlock_dp_on_error doubles as the exact "re-locked" flag,
		 * so this also stays balanced for icreate-stage failures. */
		if (!unlock_dp_on_error)
			mxfs_inode_unpin(dp);
		/* v0.3.146 P-INSTR: identify q=8 corruption error path. */
		mxfs_probe("mxfs: P-CREATE-ERR1 dialloc/icreate err=%d t_dfops_empty=%d dp_ino=%llu\n",
			error,
			list_empty(&tp->t_dfops),
			(unsigned long long)dp->i_ino);
		/* P-CR62: the dialloc'd inode `ino` failed xfs_icreate
		 * (xfs_iget) with EFSCORRUPTED but no free-state probe (P7/P9/
		 * P16) fired => not the in-core-mode!=0 check.  Decide whether
		 * dialloc handed out an inode that is LIVE on disk (double-
		 * allocation: a peer/this node already owns it) vs genuinely
		 * free-on-disk (in-core cached-struct staleness).  Read the
		 * on-disk dinode mode+gen of the very inode we tried to create. */
		/*
		 * A FAILURE BEFORE dialloc PICKED ANYTHING HAS NO DINODE TO READ.
		 * When xfs_dialloc itself fails it never assigns `ino`, which is
		 * still 0 — and reading "the dinode of inode 0" returns no magic,
		 * so the verdict below printed `disk_di_mode=0177777 ...
		 * verdict=disk-read-err/badmagic` for six hundred consecutive
		 * creates whose actual failure was an allocator errno the line
		 * never showed.  Name that case instead of inventing a disk fact
		 * about an inode number nobody handed out.
		 */
		if (mp->m_mxfs_dlm && ino == NULLFSINO) {
			mxfs_probe_ratelimited("mxfs: P-CR62 new_ino=NONE agno=n/a err=%d verdict=DIALLOC-FAILED-BEFORE-PICK — no inode number was allocated, so there is no dinode to classify; the errno above is the whole result\n",
				error);
		} else if (mp->m_mxfs_dlm) {
			extern uint16_t mxfs_dbg_disk_di_mode(struct xfs_mount *,
				xfs_ino_t, uint32_t *);
			uint32_t cr62_dgen = 0;
			uint16_t cr62_dm = mxfs_dbg_disk_di_mode(mp, ino, &cr62_dgen);
			struct xfs_inode *cr62_ip = NULL;
			(void)xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &cr62_ip);
			mxfs_probe("mxfs: P-CR62 new_ino=%llu agno=%llu err=%d disk_di_mode=0%o disk_di_gen=%u incore=%s incore_mode=0%o incore_nblk=%llu verdict=%s\n",
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
	 * block-dir peer union-merge, folded into THIS create's
	 * transaction (dp ILOCK_EXCL held + just ijoin'd, dir-EX grant already
	 * cached — NO extra DLM acquire, unlike refuted merge v1/v2).  Re-adds up
	 * to MXFS_DIR_MERGE_MAX peer dirents missing from our (possibly
	 * kept-stale/undestaged) in-core dir so xfs_dir_create_child below RMWs a
	 * UNION base instead of durably clobbering the peer's committed entries
	 * (the write-side durable lost-update — P17-CLOBBER-DROP).  Reservation
	 * headroom was added at trans-alloc.  Gated by mxfs.dir_merge.
	 */
	mxfs_dir_merge_peer_into_tp(tp, dp, MXFS_DIR_MERGE_MAX);

	/* cheap per-block reconcile of any dir DATA block the acquire-evict
	 * had to KEEP stale (in-AIL undestaged) — FUA-fold the peer's missing
	 * dirents in before xfs_dir_create_child RMWs + destages the stale base over
	 * them (the dir_reuse single-dirent loss).  Folded into THIS transaction
	 * (dp ILOCK_EXCL + dir-EX held); gated by mxfs.dir_stale_reconcile. */
	mxfs_dir_reconcile_stale_data_blocks(tp, dp);

	/* re-add any of OUR own recently-created dirents that a stale
	 * block0 adopt dropped from this dir (the node1_f1 double-block0 orphan),
	 * folded into THIS create's transaction + already-held dir EX grant — no
	 * extra DLM acquire.  Idempotent (skips names already present). */
	if (!is_dir)
		mxfs_dir_pending_replay(tp, dp, resblks);
	if (p132_t0)
		p132_tmrg = ktime_get_ns();

	error = xfs_dir_create_child(tp, resblks, &du);
	if (p132_t0)
		p132_tcc = ktime_get_ns();
	if (error) {
		/* v0.3.146 P-INSTR: identify q=8 corruption error path. */
		mxfs_probe("mxfs: P-CREATE-ERR2 dir_create_child err=%d t_dfops_empty=%d dp_ino=%llu new_ino=%llu\n",
			error,
			list_empty(&tp->t_dfops),
			(unsigned long long)dp->i_ino,
			(unsigned long long)(du.ip ? du.ip->i_ino : 0));
		goto out_trans_cancel;
	}

	/* (design review A-vs-B probe): our dirent is now in the in-core dir block,
	 * before commit.  Probe whether the base we RMW'd already LACKS a peer's
	 * durable dirent (mechanism A = stale base) vs is a superset (B = later
	 * writeback ABA).  Read-only, gated dir_postrmw_probe. */
	mxfs_dir_postrmw_probe(dp);

	/*
	 * force a freshly-created multinode directory to BLOCK format
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
			mxfs_probe("mxfs: P18-FORCEBLOCK ino=%llu sf_to_block err=%d\n",
				(unsigned long long)du.ip->i_ino, error);
			goto out_trans_cancel;
		}
	}

	/*
	 * v0.5.6: record which directory names this
	 * unpublished inode so the BAST-side publish drain can scope itself
	 * to the released dir's own children (see i_mxfs_unpub_parent in
	 * xfs_inode.h).  Covers fresh (grant_local_new) and reused
	 * (rearm_unpublished) creates — create/mkdir/mknod all land here.
	 * Plain store: a racing drain reading the pre-store 0 over-publishes,
	 * never under-publishes.
	 */
	if (du.ip)
		du.ip->i_mxfs_unpub_parent = dp->i_ino;

	/* remember this local create so we can REPLAY it if a later
	 * stale-block0 adopt drops it from this dir (the node1_f1 orphan fix).
	 * Reg-file creates only (the dir_reuse workload; dirs use other paths). */
	if (!is_dir && du.ip)
		mxfs_dir_pending_add(dp, name, du.ip);

	/* record (name -> new inum + gen) so a reader's
	 * P26-IGET-FAIL inum can be correlated: same inum => node's CURRENT
	 * inode was reverted to free; different inum => stale dir-block dirent. */
	{
		extern int mxfs_iwr_enabled;
		if (unlikely(mxfs_iwr_enabled) && du.ip && dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm))
			mxfs_probe_ratelimited(
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
	 * v0.5.4: asynchronous publish-on-mkdir,
	 * queued BEFORE the commit so the worker's ~1 ms CAW slot claim
	 * overlaps the commit + parent durable-signal (~2-3 ms) below.  The
	 * first userspace EX op on a fresh dir arrives ~60 µs after mkdir
	 * returns (ftrace/dmesg-proven: rsync's per-dir utimensat), so a
	 * post-create queue always loses the race and the
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
		/* P24 instrumented probe (capped): publish state at queue time. */
		{
			static atomic_t p24q_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p24q_n) <= 50)
				mxfs_probe("mxfs: P24-QUEUE ino=%llu mode=%o unpub=%d listed=%d\n",
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
	 * PUBLISH-BEFORE-NOTIFY — flush the parent dir's modified data
	 * blocks to the shared LUN while dp ILOCK_EXCL is still held, so the
	 * next acquirer (or our own next modify) re-reads the fresh dirent
	 * instead of clobbering from a pinned-stale buffer.  See the long note
	 * in xfs_remove.  (Distinct from the REVERTED child-AG push,
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
	 * The window it closed (peer acquires the new inode's empty
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
	 * NOTE: a synchronous-publish-of-dirs fix attempt here was
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
	 * (design review #3 "add create") — pin dp's
	 * DLM-EX grant across the ILOCK-dropped create-durability flush below
	 * (mirror of xfs_remove/xfs_rename).  Without the pin a concurrent peer
	 * BAST demotes dp EX->PR->NL in the window between this iunlock and the
	 * mxfs_dlm_dir_inode_durable(dp) call further down, so the durable flush
	 * runs at NL and the P119 non-EX guard DISCARDS the just-added dirent ->
	 * the new entry never reaches the platter -> this node's own later reload
	 * (P34D-RELOAD-FRESHSRC) FUA-reads the stale on-disk dinode and REVERTS the
	 * create (PROVEN tcp_dlm_scaling: RENAME-REVALIDATE-MISS
	 * name="n1_rNN" lookup_rc=-2 -> churn loop broke at round 94).  Bump the
	 * extra EX holder while we still hold dp ILOCK_EXCL (proves EX), drop
	 * ILOCK, and release the pin AFTER the flush (mxfs_dlm_ilock_end fires any
	 * deferred BAST via the sanctioned RELFLUSH drain).  Evaluate the durable
	 * gate ONCE here and reuse it so pin/unpin are exactly paired. */
	/* D2: runtime lever for the per-dirop
	 * synchronous parent-durability barrier — A/B-proven 7.6× per-op
	 * collapse once a dir has ANY peer contact (0.36 → 2.74 ms/op after
	 * one peer ls, permanent).  Default 1 (legacy behavior); 0 relies on
	 * the demote-drain flush + destage_kick for peer visibility. */
	{
		/* gate shared with remove/rename — mxfs_dir_op_needs_publish
		 * (dirop_virgin_skip): a self-created never-BASTed dir skips the
		 * sync publish even though i_dlm_dir_gen>0 (every used dir has it). */
		extern bool mxfs_dir_op_needs_publish(struct xfs_inode *);

		mxfs_create_dp_durable = du.ip && mxfs_dir_op_needs_publish(dp);
	}
	if (mxfs_create_dp_durable)
		mxfs_dlm_dir_hold_ex(dp);
	xfs_iunlock(dp, XFS_ILOCK_EXCL);

	/*
	 * PROACTIVE shortform-parent durability.
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
	 * — DISABLED.  Instrumented: the P112-IFLUSH-CALLER
	 * probe named THIS call (mxfs_dlm_dir_inode_durable → mxfs_inode_cluster_-
	 * durable) as the site that sets XFS_IFLUSHING on the hot SHARED parent
	 * inode cluster (e.g. the mount root ino=128) and then abandons the flush,
	 * LEAKING the cluster-buffer lock.  Every mkdir into a shared shortform
	 * parent fires this synchronous iflush_cluster+bwrite on the parent's
	 * cluster, racing concurrent creators on the SAME cluster + xfsaild + the
	 * release-path flush → an inode left IFLUSHING/in_ail with the
	 * buffer locked off-list → mxfs_ail_drain_inode_sync (BAST release drain)
	 * spins forever (P113-DRAIN-WEDGE) → SESS50-STARVE → criterion SIGKILL.
	 * (BEFORE this create-path flush was added in) had
	 * cross_visibility 4/4 with only rename wedging; this addition regressed
	 * cluster stability.  Parent-dirent visibility is the chokepoint's job: a
	 * peer that resolves the parent acquires its DLM lock, BASTs the owner, who
	 * drains+flushes the cluster on release (the mxfs_inode_cluster_-
	 * durable in bast_process is RETAINED).  Removing only the create-time
	 * proactive flush eliminates the leak without losing the release-side
	 * durability barrier.
	 */
	/* RE-ENABLED after fixing the IFLUSHING/buffer-lock leak in
	 * mxfs_inode_cluster_durable (manual xfs_bwrite on an alloc-buflist-
	 * trapped shared cluster → native delwri submit / AG-drain).  The
	 * create-path durability is NEEDED (A/B: removing it regressed
	 * unlink_visibility 1→30 fails); the leak — not the flush — was the
	 * wedge.  See mxfs_inode_cluster_durable comment. */
	/* v0.5.4 (instrumented ftrace-proven): the per-mkdir
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
	 * (PROVEN BY INSTRUMENT — 16-node cross_write_read /
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
	/* also fire for a CONTENDED dir (i_dlm_dir_gen>0 => a peer has
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
	/*  queue the fresh dinode's destage (coalesced
	 * background kick) so a peer's iget of this — possibly reused — ino
	 * reads the NEW incarnation from disk within ~ms instead of spinning
	 * on the stale/free predecessor (VISNUDGE convergence). */
	mxfs_destage_kick(mp);

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled || p132_thr > 0) &&
	    p132_t0) {
		u64 p132_end = ktime_get_ns();
		u64 p132_tot = (p132_end - p132_t0) / NSEC_PER_MSEC;

		/* res/dlk/dia are durations WITHIN pre_ms, which keeps
		 * its original meaning (t0 -> pre-commit) so earlier analyses of
		 * this line stay valid; the unattributed remainder is
		 * pre_ms - res_ms - dlk_ms - dia_ms.  Each is zero when its
		 * stamp was skipped by an error path. */
		if (p132_thr <= 0 || p132_tot >= (u64)p132_thr)
			mxfs_probe("mxfs: P132-CREATE ino=%llu parent=%llu dir=%d ag=%llu res_ms=%llu dlk_ms=%llu dia_ms=%llu rfr_ms=%llu lkp_ms=%llu icr_ms=%llu mrg_ms=%llu cc_ms=%llu pre_ms=%llu commit_ms=%llu dirsig_ms=%llu pub_ms=%llu pdur_ms=%llu total_ms=%llu lkp_fua=%llu lkp_fua_ms=%llu lkp_rd=%llu comm=%s\n",
				du.ip ? (unsigned long long)du.ip->i_ino : 0ULL,
				(unsigned long long)dp->i_ino,
				is_dir ? 1 : 0,
				du.ip ? (unsigned long long)
					XFS_INO_TO_AGNO(mp, du.ip->i_ino) : 0ULL,
				p132_tres ?
					(p132_tres - p132_t0) / NSEC_PER_MSEC : 0ULL,
				(p132_tdlk && p132_tres) ?
					(p132_tdlk - p132_tres) / NSEC_PER_MSEC : 0ULL,
				(p132_tdia && p132_tdlk) ?
					(p132_tdia - p132_tdlk) / NSEC_PER_MSEC : 0ULL,
				(p132_trfr && p132_tdia) ?
					(p132_trfr - p132_tdia) / NSEC_PER_MSEC : 0ULL,
				(p132_tlkp && p132_trfr) ?
					(p132_tlkp - p132_trfr) / NSEC_PER_MSEC : 0ULL,
				/* icr: from the lookup stamp when the lookup ran (a
				 * clustered mount), else from the refresh stamp */
				(p132_ticr && (p132_tlkp || p132_trfr)) ?
					(p132_ticr - (p132_tlkp ? p132_tlkp : p132_trfr)) / NSEC_PER_MSEC : 0ULL,
				(p132_tmrg && p132_ticr) ?
					(p132_tmrg - p132_ticr) / NSEC_PER_MSEC : 0ULL,
				(p132_tcc && p132_tmrg) ?
					(p132_tcc - p132_tmrg) / NSEC_PER_MSEC : 0ULL,
				(p132_tpre - p132_t0) / NSEC_PER_MSEC,
				(p132_tcommit - p132_tpre) / NSEC_PER_MSEC,
				(p132_tdirsig - p132_tcommit) / NSEC_PER_MSEC,
				(p132_tpub - p132_tdirsig) / NSEC_PER_MSEC,
				(p132_end - p132_tpub) / NSEC_PER_MSEC,
				p132_tot,
				(unsigned long long)p132_lkp_fua,
				(unsigned long long)(p132_lkp_fua_ns / NSEC_PER_MSEC),
				(unsigned long long)p132_lkp_rd,
				current->comm);
	}

	/*
	 * (D-32NODE-SHARED-DIR-CREATE-PACE): creates completed per
	 * DIRECTORY-GRANT TENURE.  i_dlm_epoch changes exactly when this node
	 * loses the parent's grant, so the count between changes IS the tenure.
	 *
	 * Always counted, never armed: three fields under the inode's existing
	 * flags spinlock.  Printed only when the epoch has moved, so the output
	 * is bounded by grant losses rather than by creates — the cost of a
	 * knob is that the interesting run is the one where it was off.
	 *
	 * Deliberate limitation, so a reader does not mistake it for a bug: the
	 * line for a tenure is emitted by the FIRST create of the NEXT tenure,
	 * so the last tenure on a directory before the workload stops is never
	 * reported.  That drops one sample per directory, always the final one.
	 */
	if (mp->m_mxfs_dlm) {
		unsigned long	cur = READ_ONCE(dp->i_dlm_epoch);
		u64		now = ktime_get_ns();
		u64		this_ms = p132_t0 ?
				    (now - p132_t0) / NSEC_PER_MSEC : 0;
		unsigned long	oldep = 0;
		unsigned int	oldn = 0;
		u64		oldms = 0, gap_ms = 0;

		spin_lock(&dp->i_flags_lock);
		if (dp->i_dlm_cr_epoch != cur) {
			oldep = dp->i_dlm_cr_epoch;
			oldn = dp->i_dlm_cr_n;
			oldms = dp->i_dlm_cr_ms;
			if (dp->i_dlm_cr_last_ns && now > dp->i_dlm_cr_last_ns)
				gap_ms = (now - dp->i_dlm_cr_last_ns) /
					 NSEC_PER_MSEC;
			dp->i_dlm_cr_epoch = cur;
			dp->i_dlm_cr_n = 0;
			dp->i_dlm_cr_ms = 0;
		}
		dp->i_dlm_cr_n++;
		dp->i_dlm_cr_ms += this_ms;
		dp->i_dlm_cr_last_ns = now;
		spin_unlock(&dp->i_flags_lock);

		if (oldn)
			mxfs_probe("mxfs: P483-DIRTENURE parent=%llu epoch=%lu creates=%u wall_ms=%llu mean_ms=%llu gap_ms=%llu next_epoch=%lu endsrc=%u:%u comm=%s — creates completed in one tenure of this directory's grant. gap_ms is the wait between the last create of that tenure and this one: near a full rotation means the directory really went round the fleet, a millisecond or two means it never left and the cost is not queueing\n",
				(unsigned long long)dp->i_ino, oldep, oldn,
				(unsigned long long)oldms,
				(unsigned long long)(oldms / oldn),
				(unsigned long long)gap_ms, cur,
				MXFS_SITE_ARGS(dp->i_dlm_epoch_src),
				current->comm);
	}

	xfs_parent_finish(mp, du.ppargs);

	/*
	 * cross-AG new-inode durability.
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
	 * the post-commit cross-AG / parent-AG durability push was
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
	 * v0.3.77 finding: perf_t2 ino=0x83 bmap had extents at
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
	/* < > CASCADE PROBE: pin the exact error xfs_create cancels on
	 * (the inode-reuse EAGAIN cascade shuts down via a DIRTY trans_cancel).
	 * Log error + the dir + whether the trans is dirty (dirty cancel = fatal). */
	mxfs_probe("mxfs: P-CR3-CANCEL error=%d dp_ino=%llu dialloc_ino=%llu new_ino=%llu trans_dirty=%d comm=%s\n",
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

	/* mxfs: THIS node created this O_TMPFILE nlink==0 inode and owns
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
	 * v0.5.6: a hardlink gives this inode a
	 * SECOND parent dir, which the single i_mxfs_unpub_parent scope
	 * cannot represent — a peer could then reach the inode through tdp's
	 * release without the scoped drain publishing it (the
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
 p400_retry:
	error = xfs_trans_alloc_dir(tdp, &M_RES(mp)->tr_link, sip, &resblks,
			&tp, &nospace_error);
	if (error)
		goto out_parent;

	/*
	 * MXFS (D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-AGI-RMW-399):
	 * the O_TMPFILE linkat (sip nlink==0) does an in-trans
	 * xfs_iunlink_remove — an AGI modification past the non-restartable
	 * boundary, bracketed with the AG DLM in xfs_dir_add_child since
	 * 0.23.11.  Pre-acquire sip's AG HERE, exactly as xfs_remove does for
	 * its victim: entry ILOCKs held, transaction still CLEAN, trylock +
	 * ILOCK handoff (protocol), so the deep acquire nests on the
	 * cached fast path and no task ever blocks on an AG grant while
	 * holding tdp/sip ILOCK (FIX-L3 / invariant).  -EAGAIN
	 * (handoff budget exhausted under contention) = clean cancel + retry,
	 * unbounded like xfs_remove (shape B); any other error is a
	 * clean cancel returned to the caller (nothing was dirtied).
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    VFS_I(sip)->i_nlink == 0) {
		static atomic_t	p400_tries_total = ATOMIC_INIT(0);
		int		p400_tries = 0;

		error = mxfs_trans_preacquire_inode_ags(tp, &sip, 1, &sip, 1);
		if (error) {
			xfs_trans_cancel(tp);
			xfs_iunlock(tdp, XFS_ILOCK_EXCL);
			xfs_iunlock(sip, XFS_ILOCK_EXCL);
			p400_tries = atomic_inc_return(&p400_tries_total);
			mxfs_probe_ratelimited(
			    "mxfs: P400-LINK-CLEANRETRY tdp=%llu sip=%llu rc=%d total=%d\n",
			    (unsigned long long)tdp->i_ino,
			    (unsigned long long)sip->i_ino, error, p400_tries);
			if (xfs_is_shutdown(mp)) {
				error = -EIO;
				goto out_parent;
			}
			if (error == -EAGAIN) {
				msleep(10 + get_random_u32_below(40));
				goto p400_retry;
			}
			goto out_parent;
		}
	}

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
	 *  — same producer as P206-RENAME-FTYPE-STALE.
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
				mxfs_probe("mxfs: P206-LINK-FTYPE-STALE sip=%llu name=\"%.*s\" write_ft=%u live_ft=%u live_mode=0%o gen=%u stale=%d dlm_mode=%d tdp=%llu reval=%d comm=%s — dirent ftype snapshotted before the ILOCK contradicts the inode's post-reload type\n",
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

	/* record the inode being truncated/inactivated so the AG bnobt
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
 * — D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN preflight helpers.
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
 * The preflight (reviewed design) runs BEFORE xfs_ifree,
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

/*
 * (D-0525): locate `target` on ANY of its AG's 64 unlinked bucket
 * chains and return the bucket, or -1 if it is on none.  Bounded raw walk:
 * in-core copies are consulted first (their i_next_unlinked is the truth for
 * a chain member this node has instantiated), otherwise the dinode's
 * di_next_unlinked is read from the cluster buffer.  Anomalies — a cycle-
 * length overrun or a hop to an invalid agino — return -EFSCORRUPTED.
 *
 * CALLER MUST HOLD THE AG DLM EX (the ruling's serialization requirement:
 * ILOCK + AGI buffer lock stabilize nothing against a peer's splice).  Every
 * caller today does: xfs_ifree's preflight and the orphan scan's re-verify.
 */
int
mxfs_iunlink_find_bucket(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	xfs_agino_t		target,
	short			*bucket)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_buf		*agibp;
	struct xfs_agi		*agi;
	xfs_agino_t		heads[XFS_AGI_UNLINKED_BUCKETS];
	int			b, error;

	*bucket = -1;
	if (READ_ONCE(pag->pag_dlm_holders) == 0 && mp->m_mxfs_dlm) {
		static atomic_t nh = ATOMIC_INIT(0);

		if (atomic_inc_return(&nh) <= 100)
			mxfs_probe("mxfs: P-UNLFIND-NOTENURE agno=%u agino=0x%x comm=%s — bucket find without a local AG-DLM holder\n",
				pag_agno(pag), target, current->comm);
	}
	error = xfs_read_agi(pag, tp, 0, &agibp);
	if (error)
		return error;
	agi = agibp->b_addr;
	for (b = 0; b < XFS_AGI_UNLINKED_BUCKETS; b++)
		heads[b] = be32_to_cpu(agi->agi_unlinked[b]);
	xfs_trans_brelse(tp, agibp);

	for (b = 0; b < XFS_AGI_UNLINKED_BUCKETS; b++) {
		xfs_agino_t	agino = heads[b];
		unsigned int	steps = 0;

		while (agino != NULLAGINO) {
			struct xfs_inode	*mip;
			struct xfs_imap		imap;
			struct xfs_buf		*bp;
			struct xfs_dinode	*dip;
			bool			incore = false;
			xfs_agino_t		next;

			if (agino == target) {
				*bucket = (short)b;
				return 0;
			}
			if (!xfs_verify_agino(pag, agino) || steps++ > 100000)
				return -EFSCORRUPTED;
			rcu_read_lock();
			mip = radix_tree_lookup(&pag->pag_ici_root, agino);
			if (mip && mip->i_ino) {
				next = mip->i_next_unlinked;
				incore = true;
			}
			rcu_read_unlock();
			if (incore) {
				agino = next;
				continue;
			}
			memset(&imap, 0, sizeof(imap));
			error = xfs_imap(pag, tp, xfs_agino_to_ino(pag, agino),
					 &imap, 0);
			if (error)
				return error;
			error = xfs_imap_to_bp(mp, tp, &imap, &bp);
			if (error)
				return error;
			dip = xfs_buf_offset(bp, imap.im_boffset);
			agino = be32_to_cpu(dip->di_next_unlinked);
			xfs_trans_brelse(tp, bp);
		}
	}
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
		/*
		 * (D-0525, design-consult ruling): an UNSTAMPED member's
		 * bucket is FOUND on the platter, never computed — this
		 * in-core copy came from an iget that did not reload the
		 * chain (orphan scan, export, bulkstat) and the platter's
		 * list may be slot-partitioned however this mount hashes.
		 * This is the resolve phase the ruling asked for: it runs
		 * here, under the AG DLM EX xfs_ifree holds (cluster-wide
		 * serialization of every insert/remove in this AG), with
		 * the transaction still clean.  Not on any bucket = not ours
		 * to free: fail closed (defer, reap retries).
		 */
		error = mxfs_iunlink_find_bucket(pag, tp, agino, &bucket);
		if (error || bucket < 0) {
			mxfs_probe("mxfs: P-UNLPRE-NOBUCKET ino=%llu agino=0x%x prev=0x%x nlink=%u find_rc=%d — not on any bucket; deferring\n",
				(unsigned long long)ip->i_ino, agino,
				ip->i_prev_unlinked, VFS_I(ip)->i_nlink,
				error);
			return error ? error : -EAGAIN;
		}
		mxfs_probe("mxfs: P-UNLPRE-FOUND ino=%llu agino=0x%x bucket=%d legacy_bucket=%d slot_bucket=%d — unstamped member resolved on the platter\n",
			(unsigned long long)ip->i_ino, agino, (int)bucket,
			(int)(agino % XFS_AGI_UNLINKED_BUCKETS),
			(int)(mp->m_mxfs_node_slot % XFS_AGI_UNLINKED_BUCKETS));
		ip->i_unlinked_bucket = bucket;
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
			mxfs_probe("mxfs: P-UNLPRE-LOOP ino=%llu bucket=%d hops=%ld — cycle in unlinked chain\n",
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
		mxfs_probe("mxfs: P-UNLPRE-NOTFOUND ino=%llu agino=0x%x bucket=%d head=0x%x hops=%ld\n",
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
		mxfs_probe("mxfs: P-UNLPRE-PREVMISMATCH ino=%llu agino=0x%x prev=0x%x prev_next=0x%x bucket=%d\n",
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
	 * mxfs (ino 10485889 autopsy): the EX re-acquire
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
		 * (b59r1 ino 136 autopsy): gate widened —
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
				int		ck_differs = 0;
				/*
				 * (D-TMPFILE-CHURN-the budget rule-PERF-400, design-consult
				 * ruling priority 2): mxfs_ag_buf_disk_differs is a
				 * synchronous FUA READ of the AGI (measured 0.22 ms,
				 * ~40% of xfs_inactive_ifree) charged to EVERY
				 * ifree.  It was added as containment for a stale
				 * prior-tenure in-core AGI at ifree — the class whose
				 * root (un-tenured AGI modification + undrained in-AIL
				 * AGI kept at acquire) D-399 fixed at source in
				 * 0.23.11-0.23.13.  Under a valid AG EX tenure the
				 * in-core AGI is authoritative until the release
				 * drain; the ruling: do not re-read per ifree, only
				 * on a fresh acquire after a remote grant / recovery
				 * epoch change (which the read hook already does).
				 * Knob mxfs_ifr_agi_disk_check: 1 = legacy (read +
				 * decide on disk when clean-but-divergent, the
				 * 0.23.14 default until the shadow proves clean),
				 * 2 = SHADOW: sample 1 in 64 ifrees, read, log
				 * P-IFR-AGI-STALE-SHADOW + count on a clean
				 * divergence but DECIDE ON THE IN-CORE IMAGE,
				 * 0 = off.  Zero shadow mismatches across the board
				 * + churn campaigns is the evidence for 0/2 default.
				 */
				{
					extern int mxfs_ifr_agi_disk_check;
					extern unsigned long mxfs_ifr_agi_shadow_mismatch_n;
					static atomic_t ifr_smp = ATOMIC_INIT(0);
					int mode = READ_ONCE(mxfs_ifr_agi_disk_check);
					bool do_read = mode == 1 ||
						(mode == 2 &&
						 (atomic_inc_return(&ifr_smp) & 63) == 0);

					if (do_read)
						ck_differs =
						    mxfs_ag_buf_disk_differs(ck_agibp);
				/*
				 * TAIL3: differs alone does not say
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
					if (ck_differs && mode == 2) {
						static atomic_t pifrs_n = ATOMIC_INIT(0);

						WRITE_ONCE(mxfs_ifr_agi_shadow_mismatch_n,
						    READ_ONCE(mxfs_ifr_agi_shadow_mismatch_n) + 1);
						if (atomic_inc_return(&pifrs_n) <= 100)
							mxfs_probe("mxfs: P-IFR-AGI-STALE-SHADOW ino=%llu agno=%u incore_head=0x%x disk_head=0x%x agi_gen=%llu — sampled clean-but-divergent AGI at ifree under our tenure; in-core decision kept (shadow arm)\n",
								(unsigned long long)ip->i_ino,
								pag_agno(pag),
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
						ck_differs = 0;
					}
				}

				/*
				 * (test32 ring, t=20454): this check
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
					mxfs_probe("mxfs: P-IFR-AGI-STALE ino=%llu agno=%u bucket=%d incore_head=0x%x disk_head=0x%x agi_gen=%llu — clean-but-divergent AGI; revalidating on the disk-side image\n",
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
				/* check the bucket OUR entry
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
						mxfs_probe("mxfs: P-IFR-BUCKET-MISMATCH ino=%llu computed=%d actual_head_at=%d ub=%d — entry IS listed; proceeding with free on the real bucket\n",
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
			mxfs_probe_ratelimited(
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
	 * preflight (see mxfs_ifree_unlinked_preflight above): a
	 * reclaimed-and-reaped zombie re-enters here with no in-core chain
	 * state.  Rebuild it and pin the predecessor BEFORE xfs_ifree can
	 * dirty the transaction — the mid-list unlinked remove must not be
	 * able to fail on a vanished neighbor after difree.  Any preflight
	 * failure is a clean skip: tx still clean, zombie stays durable on
	 * its bucket, the reap entry retries at cadence.
	 */
	/* (D-0525): no single-node exemption — a lone survivor faces
	 * a slot-partitioned platter too, and the fail-closed preflight is
	 * what stood between the legacy-bucket remove and the shutdown. */
	if (mp->m_mxfs_dlm &&
	    pag && xfs_inode_unlinked_incomplete(ip)) {
		error = mxfs_ifree_unlinked_preflight(tp, pag, ip,
						      &mxfs_pflt_pin);
		if (error) {
			mxfs_probe("mxfs: P-UNLPRE-SKIP ino=%llu rc=%d — deferring free; zombie durable, reap retries\n",
				(unsigned long long)ip->i_ino, error);
			xfs_trans_cancel(tp);
			xfs_iunlock(ip, XFS_ILOCK_EXCL);
			error = 0;
			goto out_unlock_ag;
		}
	}

	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	/*
	 * (D-0351, FREE-PUBLISH invariant): the unlink obligation this
	 * inode carries (armed at xfs_iunlink) is NOT discharged when the ifree
	 * below removes it from the on-disk list — it transitions to
	 * FREE_PENDING (mxfs_pubob_discharge sees i_mxfs_freeob == 1) and, at
	 * the commit, to FREE: "mode=0 at the new generation must be durable
	 * before any AG release lets a peer see this inode's inobt bit free".
	 * Measured without it (s430 dre, test1 → test2): the inobt free was
	 * published, the dinode stayed LIVE, the peer's double-alloc gate shut
	 * its filesystem down.  Continuous coverage: the AG EX is held here
	 * (holders > 0), so no release can begin between the two transitions.
	 */
	/*
	 * (D-0524): the entry becomes FREE_PENDING HERE, under the
	 * store lock, with the tenure recorded and the predecessor saved —
	 * not lazily from a completion that happens to observe the byte.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		mxfs_pubob_free_pending(mp, ip, pag ?
			READ_ONCE(pag->pag_mxfs_grant_epoch) : 0);

	error = xfs_ifree(tp, ip);
	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	if (error == -ESTALE) {
		/*
		 * Adopted-peer-free (round-5 ino 134):
		 * xfs_difree found the inobt bit for this inode already set
		 * under the held AG DLM — a peer (or an earlier pass)
		 * completed the whole free and this is a second inactivation
		 * of a mirror that adopted nlink=0 from disk.  difree aborts
		 * before its first modification, so the transaction is still
		 * clean; cancel releases the ijoin'd ILOCK.  Forget our
		 * in-core unlinked membership (the disk list no longer
		 * contains us) and succeed so the shell just reclaims.
		 */
		mxfs_probe_ratelimited(
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
		/* retire any deferred-reap entry for this ino. */
		if (mp->m_mxfs_dlm)
			mxfs_defer_reap_done(mp, ip->i_ino);
		/* (D-0351): FREE_PENDING -> FREE under the AG EX tenure
		 * we hold right now (pag_mxfs_grant_epoch; nonzero while held
		 * and no release has begun — a zero here is a protocol failure
		 * the commit helper reports).
		 * (D-0524): unconditional — the commit helper decides
		 * on the store entry under its lock (the lockless byte test
		 * here was one half of the lost update).  The fault-injection
		 * knob widens the post-commit gap so a cluster-buffer write
		 * completion lands between the commit and this call. */
		if (unlikely(READ_ONCE(mxfs_freeob_commit_delay_ms) > 0))
			msleep(READ_ONCE(mxfs_freeob_commit_delay_ms));
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
			mxfs_pubob_free_commit(mp, ip, pag ?
				READ_ONCE(pag->pag_mxfs_grant_epoch) : 0);
	} else if (mp->m_mxfs_dlm &&
		   !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		/* a failed commit has shut the log down; the helper keeps
		 * FREE_PENDING under shutdown (outcome unknowable: fail closed) */
		mxfs_pubob_free_abort(mp, ip);
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
	 * (PROVEN BY INSTRUMENT): this MUST be a targeted per-inode drain,
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
	 *  (instrumented, P137/P133/ftrace-attributed): this
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
		 * drain below cannot see a premature !in_ail (the Mode
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
				mxfs_probe_ratelimited(
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
			mxfs_probe_ratelimited(
			    "mxfs: P137-IFREE-TIME ino=%llu force_us=%llu drain_us=%llu flush_us=%llu\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)(p137_force_ns / 1000),
				(unsigned long long)(p137_drain_ns / 1000),
				(unsigned long long)(p137_flush_ns / 1000));
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: P9-INSTR ifree DONE ino=%llu agno=%u flushed",
			(unsigned long long)ip->i_ino, pag_agno(pag));
	}
	/*  with the eager chain off, hand the freed
	 * cluster's destage to the coalesced background kick (~2ms batch)
	 * so a reused ino's disk dinode converges promptly for peer iget. */
	if (pag && !error && !mxfs_ifree_eager_durable)
		mxfs_destage_kick(mp);

out_unlock_ag:
	/* (D-0351): an ifree that did not commit leaves no FREE
	 * obligation behind (the unlink obligation, if any, stays armed).
	 * (D-0524): the helper restores the recorded predecessor and
	 * is a no-op unless the entry is still FREE_PENDING (clean cancel
	 * paths: ESTALE skip, preflight skip). */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		mxfs_pubob_free_abort(mp, ip);
	if (pag) {
		mxfs_ag_dlm_unlock(mp, pag);
		xfs_perag_put(pag);
	}
	/* release the preflight's predecessor pin only after the AG
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
	/* 0.89.0 (D-0977): the open-holder guard deferred this inactivation.
	 * Nothing was freed, so the grant is RELEASED at the exit (never kept
	 * cached): the reaper's retry must take a fresh EX whose grant carries
	 * a fresh mark snapshot, or a peer's last close could never be seen. */
	bool			mxfs_b6_deferred = false;
	/* census / fix shape A: the grant this inactivation
	 * runs under — the certificate is installed from it after the acquire
	 * and revoked by its exact identity at INACT-EXREL. */
	struct mxfs_grant_result mxfs_inact_gres = { 0 };
	bool			mxfs_inact_cert = false;
	/* the EXACT installed certificate identity (the installer
	 * may advance an existing same-tenure certificate past the grant
	 * result's epoch); the INACT-EXREL revoke matches on this. */
	struct mxfs_inact_cert_id mxfs_inact_cid = { 0 };
	extern int		mxfs_inact_cert_inject;
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
	 * CLUSTERED DOUBLE-FREE GUARD (PROVEN root of the AG bnobt
	 * "ltbno+ltlen>bno" corruption).  A node can instantiate a PEER's inode
	 * grant-less (readdir / lookup / stat of a shared directory) and later
	 * observe nlink==0 after the owner unlinks it; the stale in-core inode
	 * still carries the peer's data-fork extent map.  When this node drops
	 * its last reference, xfs_inactive would truncate that stale extent map
	 * and free the peer's ALREADY-FREED blocks a second time -> AG free-space
	 * btree double-free -> EFSCORRUPTED shutdown (P47-INACT proved
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
		/* fix shape A: gen snapshot taken under i_dlm_lock
		 * before each blocking acquire (the stale-completion guard) */
		extern uint64_t mxfs_dlm_authority_gen_snapshot(struct xfs_inode *);
		extern bool mxfs_dlm_inactive_authority_install(struct xfs_inode *,
				const struct mxfs_grant_result *, uint64_t, bool,
				uint8_t *, struct mxfs_inact_cert_id *);
		uint64_t mxfs_inact_gen_snap;

		/*
		 * TOCTOU CLOSURE (design review design-consult design; see
		 * notes/sess78_inactive_toctou_fix.md).  The disk-state check
		 * below is a point-in-time read.  Under concurrent multi-node
		 * rsync TWO nodes can both hold this inode in-core with
		 * nlink==0 and both race into destructive inactivation: the
		 * loser's read saw the inode still LIVE (di_mode!=0, gen
		 * matched) at check time, the winner freed+reused it during the
		 * window, and the loser double-freed its blocks -> bnobt
		 * ltbno+ltlen>bno shutdown (proven P47-INACT verdict DISK-FREE,
		 * disk_di_gen==incore_gen+1; pinned-drain fix never
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
			 * ICLUSTER: for cluster-routed
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
			/*
			 * (D-0525): this in-core copy was instantiated
			 * by a scan that is not its bucket's owner (see
			 * MXFS_IF_FOREIGN_ZOMBIE).  No DLM acquire, no
			 * truncate, no ifree: exit plainly and let the shell
			 * reclaim; the legitimate sweeper's iget recycles it
			 * with the chain state it stamps itself.
			 */
			if (xfs_iflags_test(ip, MXFS_IF_FOREIGN_ZOMBIE)) {
				static atomic_t fz_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&fz_n) <= 200)
					mxfs_probe("mxfs: P-INACT-FOREIGN-ZOMBIE-SKIP ino=%llu gen=%u nlink=%u ub=%d prev=0x%x — not this node's bucket member; skipping destructive inactivation\n",
						(unsigned long long)ip->i_ino,
						VFS_I(ip)->i_generation,
						VFS_I(ip)->i_nlink,
						(int)ip->i_unlinked_bucket,
						ip->i_prev_unlinked);
				goto out;
			}
			mxfs_inact_via_iclus = mxfs_dlm_iclus_covered(ip);
			mxfs_inact_gen_snap = mxfs_dlm_authority_gen_snapshot(ip);
			/* (review): every attempt gets a fresh result
			 * struct so a completion can only describe THIS
			 * acquire; the routing decision above is the one
			 * snapshot used for install, unlock and census. */
			memset(&mxfs_inact_gres, 0, sizeof(mxfs_inact_gres));
			mxfs_lkrc = mxfs_inact_via_iclus ?
				mxfs_iclus_lock(mp, ip->i_ino, MXFS_LOCK_EX,
						&mxfs_inact_gres) :
				mxfs_v5_dlm_inode_lock(mp->m_mxfs_dlm,
						       ip->i_ino,
						       MXFS_LOCK_EX,
						       &mxfs_inact_gres);
			/* TEST ONLY (verification arm 4): treat a
			 * successful first acquire as the -EDEADLK contract
			 * (grant kept, caller must drop and re-acquire) and
			 * POISON the result — the retry must not be able to
			 * install from it. */
			if (unlikely(mxfs_inact_cert_inject == 3) &&
			    mxfs_lkrc == 0) {
				memset(&mxfs_inact_gres, 0xff,
				       sizeof(mxfs_inact_gres));
				mxfs_lkrc = -EDEADLK;
				pr_warn("mxfs: P-INACT-CERT-INJECT3 ino=%llu — forcing the -EDEADLK retry with a poisoned grant result\n",
					(unsigned long long)ip->i_ino);
			}
			if (mxfs_lkrc == -EDEADLK) {
				/*
				 * IUNLINK-LEAK FIX — PROVEN by
				 * run48: INACT-SKIP-STALE ino=12583085 local_unlink=1
				 * dlm_mode=3.  A peer's transient PR pull in the
				 * unlink→iput window demoted our EX; this one-shot
				 * re-acquire then hit the blocked-upgrade
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
					/* owned/nestable claim — a raw
					 * store here can overwrite a live
					 * foreign claim and the raw clear then
					 * strands its owner
					 * (D-BAST-IRELE-INACTIVE-SELF-WEDGE). */
					mxfs_dlm_claim_demoter(ip);
					mxfs_dlm_bast_process(ip);
					mxfs_dlm_release_demoter(ip);
					/* the demote moved the auth gen; a
					 * snapshot older than it would only
					 * refuse the install (STALEGEN) */
					mxfs_inact_gen_snap =
						mxfs_dlm_authority_gen_snapshot(ip);
					memset(&mxfs_inact_gres, 0,
					       sizeof(mxfs_inact_gres));
					mxfs_lkrc = mxfs_inact_via_iclus ?
						mxfs_iclus_lock(mp, ip->i_ino,
								MXFS_LOCK_EX,
								&mxfs_inact_gres) :
						mxfs_v5_dlm_inode_lock(
							mp->m_mxfs_dlm,
							ip->i_ino,
							MXFS_LOCK_EX,
							&mxfs_inact_gres);
					/* ICLUSTER: a sibling's still-draining
					 * grant re-EDEADLKs the cluster
					 * upgrade transiently; the fan-out we
					 * just armed clears it in ms. */
					if (mxfs_lkrc != -EDEADLK)
						break;
					msleep(25);
				}
				mxfs_probe("mxfs: P2I-INACT-UPG ino=%llu demote+reacquire rc=%d tries=%d (one-shot was -EDEADLK)\n",
					(unsigned long long)ip->i_ino,
					mxfs_lkrc, mxfs_upg_try + 1);
			}
			if (mxfs_lkrc == 0)
				mxfs_inact_dlm_locked = true;
			/*
			 * fix shape A: certify the tenure the freeing
			 * transactions below run under, from the completed
			 * grant result, BEFORE the first truncate/ifree dirty.
			 * Every refusal the ilock_begin path applies (proving
			 * status, gen moved, RELEASING, unpublished, routing,
			 * reclaim, relmark) applies here too and is named on
			 * the P-INACT-CERT line; a refused install leaves the
			 * images classless exactly as before (fail closed).
			 */
			if (mxfs_inact_dlm_locked) {
				static atomic_t inact_cert_n = ATOMIC_INIT(0);
				static atomic_t inact_refused_n = ATOMIC_INIT(0);
				uint8_t why = 0;

				mxfs_inact_cert = mxfs_dlm_inactive_authority_install(
						ip, &mxfs_inact_gres,
						mxfs_inact_gen_snap,
						mxfs_inact_via_iclus, &why,
						&mxfs_inact_cid);
				/* TEST ONLY (verification arm 4): force
				 * a refusal to prove no dirty follows one. */
				if (unlikely(mxfs_inact_cert_inject == 1) &&
				    mxfs_inact_cert) {
					uint8_t st; uint64_t ep;

					(void)mxfs_dlm_inactive_authority_revoke(
						ip, &mxfs_inact_cid, &st, &ep);
					mxfs_inact_cert = false;
					why = MXFS_AUTH_TRY_STALEGEN;
				}
				if (atomic_inc_return(&inact_cert_n) <= 96)
					mxfs_probe("mxfs: P-INACT-CERT ino=%llu installed=%d try=%u auth_state=%u auth_epoch=%llu gres_epoch=%llu cid_epoch=%llu kind=%u status=%u routed=%d\n",
						(unsigned long long)ip->i_ino,
						mxfs_inact_cert ? 1 : 0,
						(unsigned)why,
						(unsigned)READ_ONCE(ip->i_mxfs_auth_state),
						(unsigned long long)READ_ONCE(ip->i_mxfs_auth_epoch),
						(unsigned long long)mxfs_inact_gres.grant_epoch,
						(unsigned long long)mxfs_inact_cid.epoch,
						(unsigned)mxfs_inact_gres.kind,
						(unsigned)mxfs_inact_gres.status,
						mxfs_inact_via_iclus ? 1 : 0);
				/*
				 * (design-consult review of fix A, STOP-SHIP 1):
				 * a refused certificate must not be followed by a
				 * dirty.  The only approved classless case is an
				 * inode still on the unpublished list (UNPUB, the
				 * Q3 ruling); every other refusal — gen
				 * moved under the acquire, RELEASING, routing
				 * disagreement, non-proving grant, reclaim/
				 * shutdown, relmark — means the tenure we hold
				 * cannot be certified, so the free is DEFERRED
				 * exactly like an unreadable open bitmap (P87):
				 * the grant is released plainly at out:, the
				 * zombie stays durable on its bucket and the reap
				 * entry retries at cadence.
				 */
				if (!mxfs_inact_cert && why != MXFS_AUTH_TRY_UNPUB) {
					if (atomic_inc_return(&inact_refused_n) <= 200)
						pr_warn("mxfs: P-INACT-CERT-REFUSED ino=%llu gen=%u try=%u auth_state=%u gres_status=%u gres_epoch=%llu routed=%d bucket=%d — certificate refused; deferring destructive inactivation (no dirty under an uncertified tenure)\n",
							(unsigned long long)ip->i_ino,
							VFS_I(ip)->i_generation,
							(unsigned)why,
							(unsigned)READ_ONCE(ip->i_mxfs_auth_state),
							(unsigned)mxfs_inact_gres.status,
							(unsigned long long)mxfs_inact_gres.grant_epoch,
							mxfs_inact_via_iclus ? 1 : 0,
							(int)ip->i_unlinked_bucket);
					{
					extern int mxfs_defer_reap_cert_refused(
						struct xfs_mount *, uint64_t,
						uint32_t, int16_t);
					int nref = mxfs_defer_reap_cert_refused(
						mp, ip->i_ino,
						VFS_I(ip)->i_generation,
						ip->i_unlinked_bucket);

					/* design-consult ruling 2: a refusal
					 * that does not clear within the
					 * bounded retry budget is permanent
					 * (routing/relmark-class); escalate —
					 * never by permitting the free. */
					if (nref > MXFS_INACT_CERT_REFUSE_MAX) {
						pr_err("mxfs: P-INACT-CERT-REFUSED-ESCALATE ino=%llu refusals=%d try=%u — permanent certificate refusal; failing closed (shutdown)\n",
							(unsigned long long)ip->i_ino,
							nref, (unsigned)why);
						xfs_force_shutdown(mp,
							SHUTDOWN_CORRUPT_INCORE);
					}
					}
					goto out;
				}
			}
			/*
			 * (design-consult ruling, D-FOREIGN-SLICE-INTENTS-
			 * ABANDONED attribution): name the tenure the freeing
			 * transactions below will be captured under, next to
			 * the certificate state the classifier will read.  The
			 * decisive census is "a real matching EX tenure existed
			 * at first dirty and certificate absence was the sole
			 * classification failure" — this line is the tenure
			 * half, P239-OWNAUTH-NONDUR (same ino) the other.
			 */
			{
				static atomic_t inact_ex_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&inact_ex_n) <= 96)
					mxfs_probe("mxfs: P-INACT-EX ino=%llu rc=%d via_iclus=%d resource=%llu epoch=%llu lineage=%llu kind=%u gmode=%u dlm_mode=%u auth_state=%u auth_epoch=%llu nlink=%u local_unlink=%d\n",
						(unsigned long long)ip->i_ino,
						mxfs_lkrc,
						mxfs_inact_via_iclus ? 1 : 0,
						(unsigned long long)mxfs_inact_gres.resource,
						(unsigned long long)mxfs_inact_gres.grant_epoch,
						(unsigned long long)mxfs_inact_gres.resource_lineage,
						(unsigned)mxfs_inact_gres.kind,
						(unsigned)mxfs_inact_gres.mode,
						(unsigned)READ_ONCE(ip->i_dlm_mode),
						(unsigned)READ_ONCE(ip->i_mxfs_auth_state),
						(unsigned long long)READ_ONCE(ip->i_mxfs_auth_epoch),
						VFS_I(ip)->i_nlink,
						xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK) ? 1 : 0);
			}
			/*
			 * PROVEN BY INSTRUMENT root of the
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
			 * the budget rule FIX — dlm_scaling@32
			 * NO_TERMINAL_RECORD (~15-19 ops/s vs floor 30): after
			 * the nlink-read skip below, the mode/gen read
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
				 * finding-B discriminator (instrumented):
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
							mxfs_probe("mxfs: P-B-MODE-DIVERGE ino=%llu raw_mode=0%o raw_gen=%u coh_mode=0%o coh_gen=%u — authority guard raw disk-mode read diverges from coherent read\n",
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
			 * the coherent-nlink read feeds ONLY
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
		 *   inode + leave it on the AGI unlinked list — risk).
		 */
		/*
		 * B3 (design review design-consult): the killer case B1/B2 both
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
		/* C8: adopted (survivor-sweep) freer authority — see
		 * MXFS_IF_ADOPTED_UNLINK.  Grants B3/B4 authority, never the
		 * P2L-OWNFREE bypass. */
		bool mxfs_adopted_unlink =
			xfs_iflags_test(ip, MXFS_IF_ADOPTED_UNLINK);
		/*
		 *  (instrumented — BUG3 hunt, fence_during_write@
		 * 8/caw): B2's own comment above says "Only skip when we are
		 * GRANT-LESS (i_dlm_mode==NL)" but the check below never
		 * implemented that qualifier.  A same-session attempt to ADD
		 * that check (matching B4/B5's `!= MXFS_LOCK_EX` pattern) was
		 * REJECTED after two independent model consults (design review,
		 * design review/Opus): live captures show this firing with
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
			/* 3000→300 — printk-storm DoS (see P82-ADD). */
			static atomic_t p2lex_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p2lex_n) <= 300)
				mxfs_probe("mxfs: P2L-EX-GENMIS ino=%llu incore_gen=%u disk_gen=%u dlm_mode=%u dlm_locked=%d local_unlink=%d ip=%px pid=%d comm=%s — gen-mismatch B2-skip fired while holding a non-NL grant (forensic only, NOT proceeding destructively — see comment above)\n",
					(unsigned long long)ip->i_ino,
					mxfs_igen, mxfs_dgen, ip->i_dlm_mode,
					mxfs_inact_dlm_locked ? 1 : 0,
					mxfs_local_unlink ? 1 : 0,
					ip, current->pid, current->comm);
		}

		/*
		 * B3: torn/stale in-core copy of a peer's STILL-LINKED
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
		 * B5: the per-inode EX grant acquire
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
		 * TOCTOU-CLOSURE EXTENSION (PROVEN: P47-INACT inact_ino=2099107
		 * disk_di_mode=0 disk_di_gen=incore_gen+1 — a stale gen-G cached inode
		 * the peer freed+reused to gen G+1; this node double-freed block 297 in
		 * agno=1 -> ltbno+ltlen>bno shutdown).  The original B5 required
		 * !mxfs_local_unlink, but MXFS_IF_LOCAL_UNLINK LEAKS across inode-number
		 * REUSE: it was set when THIS node unlinked the gen-G incarnation in a
		 * PRIOR round, and (because the stale copy was never reloaded —
		 * clear-on-reload didn't run) it still reads 1 for the dead
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
		 * (design review audit C2): the log-recovery exemption is GONE.
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
		 * instrumentation: log the B3
		 * decision INPUTS unconditionally for every multi-node nlink==0
		 * inactivation, so a shutdown's pre-free state is captured even
		 * when the guard does NOT skip (the failing case).  P19-B3DEC.
		 */
		/* capped, NOT ratelimited — run68's decisive
		 * B-decision (ifree of the about-to-be-reused inum) was
		 * ratelimit-suppressed in the rm-rf storm. */
		{
		/* 8000→300 — printk-storm DoS (see P82-ADD). */
		static atomic_t p19_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p19_n) <= 300)
		mxfs_probe("mxfs: P19-B3DEC ino=%llu agno=%u incore_gen=%u disk_mode=0%o disk_gen=%u coh_nlink=%d local_unlink=%d dlm_mode=%u dlm_locked=%d will_skip=%d (b1_diskfree=%d b2_genmis_raw=%d b2_reused=%d b3_tornlive=%d b4_noauth=%d b5_nolock=%d) ip=%px pid=%d comm=%s\n",
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
		 * OWN-FREE BYPASS (proven by instrument, ino 680 autopsy):
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
			 * a skip WITH local-unlink intent means the
			 * rightful freer is bailing — that leaks the inode on its AGI
			 * unlinked bucket (nobody else will free it; peers' B4/B5 skip
			 * too) and poisons the next same-bucket insert.  Post-fix
			 * (P2I demote+reacquire above) this must be ZERO; log it
			 * UNRATELIMITED so any residual leak is visible in one run.
			 */
			/* CAP 300 (was deliberately unlimited).
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
			mxfs_probe_ratelimited("mxfs: INACT-SKIP-STALE ino=%llu agno=%u incore_mode=0%o incore_gen=%u disk_mode=0%o disk_gen=%u coh_nlink=%d dlm_mode=%u local_unlink=%d reason=%s — skipping destructive inactivation to avoid double-free ip=%px pid=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				(unsigned)XFS_INO_TO_AGNO(mp, ip->i_ino),
				(unsigned)VFS_I(ip)->i_mode, mxfs_igen,
				(unsigned)mxfs_dmode, mxfs_dgen,
				(int)mxfs_coh_nlink, ip->i_dlm_mode,
				mxfs_local_unlink ? 1 : 0, mxfs_reason,
				ip, current->pid, current->comm);
			/*
			 * UNLEAK (proven by instrument: the P2L-INACT-LEAK
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
	 * B6 — OPEN-DEFER (D-CROSSNODE-OPEN-UNLINK-DATA-LOSS / design review
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
			/* ROUTED inode — we hold the CLUSTER EX, not
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
		 * (design review audit C5): FAIL CLOSED.  We hold the inode EX,
		 * so the bitmap read must succeed; an unreadable bitmap is
		 * indistinguishable from "a peer holds this open" and the
		 * only safe verdict is defer.
		 *
		 * 0.89.0 (D-0977): -EOPNOTSUPP is no longer a proceed verdict.
		 * Both transports carry open-holder marks now (TCP: the mask
		 * snapshot on this EX grant, mxfs_v5_dlm_inode_open_holders);
		 * the one registry-less configuration left is a cluster-ROUTED
		 * inode on TCP, which the mount gate refuses — so an
		 * -EOPNOTSUPP here means the guard cannot see the peers and
		 * must defer, exactly like any other unreadable bitmap.  The
		 * old proceed-on-EOPNOTSUPP is how a peer's held descriptor
		 * came to read the successor file's bytes (measured s62d).
		 */
		/* 0.89.1 (D-0977 instrument): what the guard read, every time */
		mxfs_probe_ratelimited(
		    "mxfs: P87-OPEN-CHECK ino=%llu gen=%u rc=%d open_holders=0x%llx self=0x%llx routed=%d dlm_mode=%u\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_generation,
			mxfs_oh_rc, (unsigned long long)mxfs_oh,
			(unsigned long long)mxfs_self,
			mxfs_dlm_iclus_covered(ip) ? 1 : 0, ip->i_dlm_mode);
		if (mxfs_oh_rc) {
			mxfs_probe_ratelimited(
			    "mxfs: P87-OPEN-DEFER-ERR ino=%llu gen=%u rc=%d — open bitmap unreadable under EX; failing CLOSED (deferring free)\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_generation, mxfs_oh_rc);
			mxfs_defer_reap_add(mp, ip->i_ino,
					    VFS_I(ip)->i_generation,
					    ip->i_unlinked_bucket);
			mxfs_b6_deferred = true;
			goto out;
		}
		if (mxfs_oh & ~mxfs_self) {
			mxfs_probe_ratelimited(
			    "mxfs: P87-OPEN-DEFER ino=%llu gen=%u open_holders=0x%llx self=0x%llx bucket=%d — peer holds this unlinked inode open; deferring destructive inactivation\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_generation,
				(unsigned long long)mxfs_oh,
				(unsigned long long)mxfs_self,
				(int)ip->i_unlinked_bucket);
			mxfs_defer_reap_add(mp, ip->i_ino,
					    VFS_I(ip)->i_generation,
					    ip->i_unlinked_bucket);
			mxfs_b6_deferred = true;
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

	/*
	 * (docs/dir-sharding.md): a sharded PARENT directory owns a
	 * set of container inodes named only by its manifest.  Free them (and
	 * the manifest holder) BEFORE the parent's own truncate/ifree; on
	 * error the parent stays on the unlinked list and the next pass
	 * (inactivation, or a survivor's unclaimed-bucket sweep, which reaches
	 * this same function) restarts the walk.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) && mxfs_is_dirshard_parent(ip) &&
	    VFS_I(ip)->i_nlink == 0) {
		error = mxfs_dirshard_inactive_parent(ip);
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
		mxfs_probe_ratelimited(
		    "mxfs: P137-INACT-TIME ino=%llu total_us=%llu dlm_us=%llu fua_us=%llu trunc_us=%llu ifree_us=%llu\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)((ktime_get_ns() - p137_t0) / 1000),
			(unsigned long long)(p137_dlm_ns / 1000),
			(unsigned long long)(p137_fua_ns / 1000),
			(unsigned long long)(p137_trunc_ns / 1000),
			(unsigned long long)(p137_ifree_ns / 1000));
	/*
	 * release the per-inode DLM EX grant taken to serialize
	 * clustered destructive inactivation (idempotent — caw_unlock is a
	 * no-op if not held).  Done before dquot detach; no XFS ILOCK held.
	 */
	if (mxfs_inact_dlm_locked &&
	    mxfs_inact_defer_unlock && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    !mxfs_b6_deferred &&
	    (atomic_read(&ip->i_pincount) > 0 ||
	     (ip->i_itemp &&
	      (ip->i_itemp->ili_fields ||
	       test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags))))) {
		/*
		 *  FIX-1 (instrumented, PROVEN via
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
		mxfs_probe_ratelimited(
		    "mxfs: P128-INACT-DEFER ino=%llu pin=%d ili=0x%x in_ail=%d — freed dinode undestaged; keeping grant cached\n",
			(unsigned long long)ip->i_ino,
			atomic_read(&ip->i_pincount),
			ip->i_itemp ? ip->i_itemp->ili_fields : 0,
			(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
				&ip->i_itemp->ili_item.li_flags)) ? 1 : 0);
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
		/* fix shape A: the certificate stays with the cached
		 * grant; from here the release side owns it (BAST durable
		 * loop or mxfs_dlm_evict, which asserts it: P-INACT-CERT-
		 * EVICT). */
		if (mxfs_inact_cert) {
			extern void mxfs_dlm_inactive_authority_defer(
					struct xfs_inode *);
			mxfs_dlm_inactive_authority_defer(ip);
		}
	} else if (mxfs_inact_dlm_locked) {
		extern void mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *,
							  uint64_t);
		extern void mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *,
						     uint64_t);
		extern int mxfs_iclus_unlock(struct xfs_mount *, uint64_t,
					     uint8_t, bool);
		/*
		 *  /use the free-aware unlock so
		 * CAW piggybacks a dir_epoch/last_ex_slot clear onto its own
		 * tombstone CAS (zero extra I/O) so the NEXT node to reuse
		 * this ino number doesn't inherit a stale cross-node-handoff
		 * signal from this now-dead incarnation (dlm_scaling@32
		 * op-rate fix).  Also handled at the mxfs_dlm_evict site
		 * (xfs_mxfs_dlm.c) for any freed inode whose release didn't
		 * take this synchronous inactivation-lock path.
		 *
		 * (D-AGI-UNLINKED tombstone-semantics): the old gate
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
		extern int mxfs_dlm_inactive_authority_revoke(struct xfs_inode *,
				const struct mxfs_inact_cert_id *, uint8_t *,
				uint64_t *);

		/*
		 * /469 fix shape A: the ifree-end drain above destaged
		 * everything this tenure dirtied; revoke the certificate by
		 * the EXACT identity that was installed (read back at install,
		 * so an ADVANCE to a newer epoch is matched too) BEFORE the raw
		 * release below makes the relinquishment peer-visible.
		 * Nothing dirties after this point (the tombstone/unlock is a
		 * DLM CAS, not a buffer).
		 *
		 * Outcomes (design-consult review STOP-SHIP 3): REVOKED is the only
		 * normal one.  GONE (no proving certificate left) leaves
		 * nothing that could outlive the grant — counted and loud.
		 * FOREIGN (a DIFFERENT proving certificate on an I_FREEING
		 * inode we hold raw EX on) is an invariant violation: nothing
		 * else may install here, and releasing the grant under it
		 * would let that certificate outlive its tenure.  Fail closed:
		 * shut the filesystem down before the release.
		 */
		if (mxfs_inact_cert) {
			uint8_t st = 0;
			uint64_t ep = 0;
			int rv;

			/* TEST ONLY (verification arm 6): corrupt the
			 * saved identity so the revoke must miss FOREIGN. */
			if (unlikely(mxfs_inact_cert_inject == 2))
				mxfs_inact_cid.epoch ^= 1;
			rv = mxfs_dlm_inactive_authority_revoke(ip,
						&mxfs_inact_cid, &st, &ep);
			if (rv != MXFS_INACT_REVOKED)
				pr_warn("mxfs: P-INACT-CERT-REVOKE-MISS ino=%llu rv=%d auth_state=%u auth_epoch=%llu cid_epoch=%llu cid_res=%llu gres_epoch=%llu — certificate at INACT-EXREL is not the one this inactivation installed\n",
					(unsigned long long)ip->i_ino, rv,
					(unsigned)st,
					(unsigned long long)ep,
					(unsigned long long)mxfs_inact_cid.epoch,
					(unsigned long long)mxfs_inact_cid.resource,
					(unsigned long long)mxfs_inact_gres.grant_epoch);
			if (rv == MXFS_INACT_REVOKE_FOREIGN) {
				pr_err("mxfs: P-INACT-CERT-FOREIGN ino=%llu — a proving certificate that is not this inactivation's tenure would outlive the grant release; failing closed (shutdown)\n",
					(unsigned long long)ip->i_ino);
				xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
			} else if (rv == MXFS_INACT_REVOKE_GONE) {
				/* design-consult re-review STOP-SHIP 1: the
				 * certificate was moved by a release-side actor
				 * while this inactivation was dirtying under it
				 * (P-INACT-CERT-LOST names the actor).  Images
				 * formatted after that point are classless, and
				 * the actor believed the tenure over while we
				 * still wrote under it.  Fail closed. */
				pr_err("mxfs: P-INACT-CERT-GONE ino=%llu auth_state=%u — inactivation certificate lost before INACT-EXREL; failing closed (shutdown)\n",
					(unsigned long long)ip->i_ino,
					(unsigned)st);
				xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
			}
		}

		/*
		 * open tracking — clear at inactivation exit.  We are
		 * past the last local iput (VFS evict truncated the pages) so
		 * this node provably has no protected activity left; waiting
		 * for xfs_reclaim (memory pressure) leaves a peer's deferred
		 * reap stuck behind our stale bit for minutes (measured: the
		 * openunlink probe's reaper retried forever while the closer's
		 * zombie sat RECLAIMABLE).  Applies to every nlink==0 exit —
		 * guard-skips, B6 defers, and plain paths — except a committed
		 * free, whose unlock_free already zeroed the whole field.
		 *
		 * 0.89.0 (D-0977): the clear RIDES the plain release below
		 * (MXFS_TAUTH_OPEN_CLEAR), the only form that is durable on
		 * the TCP ledger; on CAW the same op folds into the release
		 * CAS.  The standalone CAW clear stays for the ICLUSTER arm,
		 * whose unlock ignores the op.
		 */
		{
		extern bool mxfs_v5_dlm_open_clear_rides_release(struct mxfs_v5_dlm *);
		extern int mxfs_v5_dlm_inode_unlock_open(struct mxfs_v5_dlm *,
							 uint64_t, uint32_t, int);
		bool mxfs_open_rel = ip->i_mxfs_open_pub &&
			VFS_I(ip)->i_nlink == 0 && !mxfs_freed &&
			!mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm);

		if (mxfs_inact_via_iclus) {
			/* ICLUSTER release_check: is_free piggybacks the
			 * tombstone CAS iff this call performs the cluster
			 * release (pending BAST + clean sweep). */
			(void)mxfs_iclus_unlock(mp, ip->i_ino, MXFS_LOCK_EX,
						mxfs_freed);
			if (mxfs_open_rel &&
			    !mxfs_v5_dlm_open_clear_rides_release(mp->m_mxfs_dlm))
				mxfs_v5_dlm_inode_open_clear(mp->m_mxfs_dlm,
							     ip->i_ino);
		} else if (mxfs_freed) {
			mxfs_v5_dlm_inode_unlock_free(mp->m_mxfs_dlm,
						      ip->i_ino);
		} else {
			mxfs_v5_dlm_inode_unlock_open(mp->m_mxfs_dlm, ip->i_ino,
						      0, mxfs_open_rel ? -1 : 0);
		}
		if (mxfs_open_rel)
			ip->i_mxfs_open_pub = false;
		}
		}
		/*
		 * instrumented probe: the ON-DISK slot for this ino is now
		 * released, but in-core i_dlm_mode/i_dlm_unpublished are left
		 * as-is.  If this in-core inode is later RECYCLED for a new
		 * local create, publish-on-create bails (unpub flag clear) and
		 * the create runs on a phantom EX with no slot.  Pair with
		 * P128-PUBLISH-BAIL on the same ino.
		 */
		mxfs_probe_ratelimited(
		    "mxfs: P128-INACT-EXREL ino=%llu dlm_mode=%u unpub=%d freed=%d\n",
			(unsigned long long)ip->i_ino, ip->i_dlm_mode,
			ip->i_dlm_unpublished ? 1 : 0,
			xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED) ? 1 : 0);
		/* close the sanctioned inactivation
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
	bool			cached_before;

	ASSERT(next_agino != NULLAGINO);

	/*
	 * P84-UNL-RELOAD-CACHED.  Was next_agino ALREADY in this node's
	 * inode cache when we got here?  Upstream asserts it is not, but only
	 * under DEBUG, so on a production build the question has never been
	 * answered — and it decides the disposition of the shutdown below.
	 * xfs_iget returns a CACHED inode when one exists, and XFS_IGET_UNTRUSTED
	 * changes validation, not freshness: it is not a "fetch the freshest
	 * shared-disk copy" flag.  So a cache hit here means the nlink we are
	 * about to judge came from THIS node's memory, not from the LUN, and a
	 * stale in-core copy of a peer's inode would be indistinguishable from
	 * real AGI corruption.  Recorded before the iget so the answer is not
	 * perturbed by the iget itself.
	 */
	rcu_read_lock();
	cached_before = radix_tree_lookup(&pag->pag_ici_root, next_agino) != NULL;
	rcu_read_unlock();
	next_ip = NULL;

	xfs_info_ratelimited(mp,
 "Found unrecovered unlinked inode 0x%x in AG 0x%x.  Initiating recovery.",
			next_agino, pag_agno(pag));
	/* D-AGI-UNLINKED canary detail (unconditional — this reload is
	 * the rare precursor of the cross-node stale-stitch shutdown): under
	 * multi-node, next_agino here is typically a PEER's in-flight unlinked
	 * inode our cache never saw.  Log the stitch parameters + AG tenure
	 * gen so the fleet-wide merge orders this against both nodes' P82/P83
	 * records. */
	if (mp->m_mxfs_dlm)
		mxfs_probe("mxfs: P83-UNL-RELOAD agno=%u prev_agino=0x%x next_agino=0x%x agi_gen=%llu node_slot=%u realns=%llu\n",
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
		/*
		 * P84-UNL-RELOAD-LIVE.  THIS is the branch that killed
		 * test25 at 32/caw on 2026-08-20 and cascaded to 15 more nodes:
		 * it is the only -EFSCORRUPTED in this function, it fires inside
		 * xfs_droplink's ALREADY-DIRTY rename transaction, and
		 * xfs_trans_cancel then force-shuts the filesystem
		 * (D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361 ->
		 *  D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN).
		 *
		 * MEASUREMENT ONLY -- the verdict is unchanged.  Per the
		 * Design-consult ruling (ccmemory
		 * docs/rulings/agi-unlinked-reload-stale-live.md)
		 * the destructive "heal" the sibling -ENOENT branch uses is NOT
		 * safe here: a FREE inode cannot be a live unlinked-list member,
		 * so cutting it loses nothing, but an ALLOCATED inode with
		 * nlink!=0 may be a peer's real chain, and discarding it orphans
		 * everything behind it.  Before any behaviour changes, the
		 * evidence has to say WHICH of these it is:
		 *   cached=1            -> our own stale in-core copy; the LUN was
		 *                          never consulted (the leading hypothesis,
		 *                          and the one upstream's DEBUG-only ASSERT
		 *                          was written to catch)
		 *   cached=0, nlink>0   -> the home dinode itself still reads
		 *                          linked: either the peer's nlink=0 image
		 *                          is not yet visible at DLM handoff (a
		 *                          release-side visibility defect, NOT a
		 *                          defect here) or the AGI really dangles
		 */
		pr_warn("mxfs: P84-UNL-RELOAD-LIVE agno=%u bucket=%d prev_agino=0x%x next_agino=0x%x ino=%llu cached=%d nlink=%u mode=0x%x gen=%u next_unlinked=0x%x agi_gen=%llu node_slot=%u comm=%s — the reloaded unlinked-list member is LINKED; upstream calls this AGI corruption and force-shuts the FS from inside a DIRTY transaction\n",
			pag_agno(pag), (int)bucket, prev_agino, next_agino,
			(unsigned long long)next_ip->i_ino,
			cached_before ? 1 : 0,
			VFS_I(next_ip)->i_nlink,
			VFS_I(next_ip)->i_mode,
			VFS_I(next_ip)->i_generation,
			next_ip->i_next_unlinked,
			(unsigned long long)agibp->b_mxfs_ag_gen,
			mp->m_mxfs_node_slot, current->comm);
		xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
		error = -EFSCORRUPTED;
		goto rele;
	}

	if (mp->m_mxfs_dlm)
		mxfs_probe_ratelimited("mxfs: P84-UNL-RELOAD-OK agno=%u bucket=%d next_agino=0x%x cached=%d gen=%u node_slot=%u — reloaded member is genuinely unlinked (base rate for P84-UNL-RELOAD-LIVE)\n",
			pag_agno(pag), (int)bucket, next_agino,
			cached_before ? 1 : 0, VFS_I(next_ip)->i_generation,
			mp->m_mxfs_node_slot);
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
	/* (d): a live publication obligation's dirty conversion must
	 * never evaporate silently — this is the ISTALE chunk-free clearing
	 * path; a PUBOB-armed inode here means an allocated unlinked-list
	 * member's chunk is being freed under it (btree inconsistency family).
	 * Loud, with the caller. */
	if (xfs_iflags_test(ip, MXFS_IF_PUBOB) &&
	    !xfs_iflags_test(ip, MXFS_IF_PUBOB_FLUSHED)) {
		mxfs_probe("mxfs: P88-PUBOB-FIELDSCLEAR ino=%llu site=mark_stale fields=0x%x nlink=%u comm=%s\n",
			(unsigned long long)ip->i_ino, iip->ili_fields,
			VFS_I(ip)->i_nlink, current->comm);
		mxfs_probe_stack();
	}
	spin_lock(&iip->ili_lock);
	iip->ili_last_fields = iip->ili_fields;
	iip->ili_fields = 0;
	spin_unlock(&iip->ili_lock);
	ASSERT(iip->ili_last_fields);

	/* (D-0532 option (a)): the ILOCK on a chunk sibling was taken
	 * by xfs_ilock_nowait (no DLM begin) — and every sibling here is a
	 * DEFERRED-freed corpse still holding its cached EX grant, so a plain
	 * xfs_iunlock would be an unpaired end.  Release the rwsem only. */
	if (ip != free_ip)
		xfs_iunlock_nodlm(ip, XFS_ILOCK_EXCL);
	return;

out_iunlock:
	if (ip != free_ip)
		xfs_iunlock_nodlm(ip, XFS_ILOCK_EXCL);
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
		mxfs_pal_log(MXFS_LOG_DEBUG,
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
	 * publish an inode-eviction hint into the disklock heartbeat
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
	/* IFREE ledger — pairs with P4X-UNLINK: names when
	 * each inode number went free and by whom (run22 dangler autopsy). */
	{
		extern int mxfs_dirwr_enabled;

		if (unlikely(mxfs_dirwr_enabled) && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			static atomic_t p4i_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p4i_n) <= 200000)
				mxfs_probe("mxfs: P4I-IFREE ino=%llu err=%d gen=%u cluster_deleted=%d comm=%s realns=%llu\n",
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
	/* FIX-C: bounded clean-trans retries for the post-lock child-AG
	 * acquire below (replaces the pre-lock hold — see comment there). */
	int			p13_tries = 0;
	/* P133 (instrumented): stage timing for the tcp
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

	/*  (Phase A): never mutate a POISONED dead dir
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
	 * (MODE B fix): refresh a peer-stale SHORTFORM dir base BEFORE we
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
	 * FIX-C (PROVEN BY INSTRUMENT, ladder-r16 P12-HOLDERTASK/P36-STACK):
	 * the pre-lock child-AG hold PARKED this task holding AG-EX
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
		/* (D-501): the victim's AG stays MANDATORY — the
		 * in-trans iunlink/difree past the dirty boundary is the
		 * genuine non-restartable demand the ruling preserves. */
		error = mxfs_trans_preacquire_inode_ags(tp, &ip, 1, &ip, 1);
		if (error) {
			xfs_trans_cancel(tp);
			xfs_iunlock(ip, XFS_ILOCK_EXCL);
			xfs_iunlock(dp, XFS_ILOCK_EXCL);
			/*
			 * (design-consult ruled, shape B): -EAGAIN =
			 * preacquire handoff budget exhausted under
			 * contention; the retry is UNBOUNDED — contention
			 * must never surface as an errno (the old 3-try cap
			 * converted it to a spurious -ETIMEDOUT).  Genuine
			 * cluster failure exits via the shutdown check.
			 * Other errors keep the bounded 3-try retry.
			 */
			if (error == -EAGAIN) {
				++p13_tries;
				mxfs_probe_ratelimited(
				    "mxfs: P13-CLEANRETRY remove dp=%llu ip=%llu try=%d rc=%d\n",
				    (unsigned long long)dp->i_ino,
				    (unsigned long long)ip->i_ino,
				    p13_tries, error);
				if (xfs_is_shutdown(mp)) {
					error = -EIO;
					goto out_parent;
				}
				msleep(10 + get_random_u32_below(
						40 * umin(p13_tries, 10)));
				goto p13_retry;
			}
			if (++p13_tries < 3) {
				mxfs_probe_ratelimited(
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
	 * cross-node defensive re-validation BEFORE the transaction is
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
	 * MODIFY-side acquire cold-read (the missing half of the
	 * PAIR — only added it to the READ path xfs_lookup).
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

	/*
	 * (docs/dir-sharding.md): rmdir of a SHARDED directory.  Its
	 * own dir2 holds only "." and "..", so xfs_dir_remove_child's emptiness
	 * test would pass on a directory full of files and the inactivation
	 * would free the containers around them.  ip is ILOCK_EXCL here — the
	 * parent barrier, so no pin holder can add an entry — and the
	 * transaction is still clean: a non-empty set is a clean -ENOTEMPTY.
	 */
	if (is_dir && mxfs_is_dirshard_parent(ip)) {
		error = mxfs_dirshard_isempty(ip);
		if (error)
			goto out_trans_cancel;
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
	 * PUBLISH-BEFORE-NOTIFY (dir-block lost-update fix).
	 *
	 * PROVEN root (instrumented): under 4-node concurrent rename/unlink of
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
	 * fix is self-reinforcing.  Differs from the release-side flush
	 * (REVERTED): that ran at BAST handoff where the buffer could already be
	 * stale from a failed pinned re-read; at commit it is always fresh.
	 */
	mxfs_dlm_dir_durable_signal(dp);

	if (is_dir && xfs_inode_is_filestream(ip))
		xfs_filestream_deassociate(ip);

	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	/*
	 * make the SHORTFORM parent's just-committed REMOVAL durable on
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
	/* also fire for a CONTENDED dir (gen>0) even if self-created —
	 * see the matching note in xfs_create.  This is the uv shortform-delete
	 * durability gap: node2's last 10 deletes happen after the block->sf
	 * conversion, so the data-block publish (durable_signal) no-ops and only
	 * this inode-cluster flush makes node2's removal visible to node1. */
	/*
	 * PROVEN FIX: pin dp's DLM-EX grant across the
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
		/* one gate for create/remove/rename — see
		 * mxfs_dir_op_needs_publish (dirop_virgin_skip) in xfs_mxfs_dlm.c:
		 * a self-created never-BASTed dir no longer pays the sync publish
		 * just because i_dlm_dir_gen>0 (which every used dir has). */
		extern bool mxfs_dir_op_needs_publish(struct xfs_inode *);
		bool dp_durable = mxfs_dir_op_needs_publish(dp);

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
			mxfs_probe("mxfs: P133-REMOVE ino=%llu parent=%llu durable=%d self_created=%d dgen=%llu pfmt=%d commit_ms=%llu pdur_ms=%llu\n",
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
	/* route through std_return so the P4X-UNLINK ledger
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
	/* UNLINK ledger (instrumented): run22's dangling-dirent
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
				mxfs_probe("mxfs: P4X-UNLINK pino=%llu name=[%.*s] cino=%llu err=%d nlink=%u comm=%s realns=%llu\n",
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
	int			preacq_tries = 0;
	int			error, nospace_error = 0;

	trace_xfs_rename(src_dp, target_dp, src_name, target_name);

	/* P217 cookie (D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361):
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

	/*  (Phase A): refuse renames touching a
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
	 * v0.5.6: a CROSS-directory rename moves a
	 * still-unpublished inode out from under its recorded
	 * i_mxfs_unpub_parent, so the scoped BAST publish drain of the NEW
	 * parent would miss it — a peer could reach it through target_dp's
	 * release and acquire its empty CAW slot cleanly (the hole).
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
	 * (MODE B fix): refresh peer-stale SHORTFORM src/target dir bases
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
	/*
	 * 0.84.11 (D-0958): the set acquire is a FALLIBLE boundary — the
	 * transaction is reserved and clean, nothing is joined, and the only
	 * work behind it (the whiteout's own committed allocation, the parent
	 * pointer args, the dquot attach) is unwound by the ordinary error
	 * path that a failed dquot attach already takes.  A refused member
	 * releases the whole set and fails the rename with the refusal's
	 * errno; nothing is ever cancelled dirty here.
	 */
	if (mp->m_mxfs_dlm) {
		error = mxfs_lock_inodes_fallible(inodes, num_inodes,
						  XFS_ILOCK_EXCL);
		if (unlikely(error)) {
			mxfs_namespace_refused(src_dp, "rename", error);
			xfs_trans_cancel(tp);
			goto out_tgt_ppargs;
		}
	} else {
		xfs_lock_inodes(inodes, num_inodes, XFS_ILOCK_EXCL);
	}

	/* D-0515 backstop: refused DLM acquires on any participant
	 * fail the rename here, while the transaction is still clean. */
	{
		int qi;

		for (qi = 0; qi < num_inodes; qi++) {
			error = mxfs_quar_gate_locked(inodes[qi], "rename");
			if (unlikely(error))
				goto out_trans_cancel;
		}
	}

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
	 * MXFS (repositioned FIX-C): acquire the per-AG DLM
	 * grants for every participating inode's AG, ascending, so the deep
	 * allocator/defer acquires below nest on the fast path and never
	 * block cross-node with the transaction DIRTY (120s timeout -> dirty
	 * cancel -> shutdown).  The transaction is still clean here, so a
	 * (rare) acquire failure is a clean cancel with no shutdown.
	 *
	 * FIX-C: this call used to sit BEFORE xfs_lock_inodes, which
	 * parked this task holding AG grants while waiting for entry-lock DLM
	 * grants — the exact hold-and-wait edge (mirror of the xfs_remove
	 * pre-lock hold, see the P12-HOLDERTASK stack there) that
	 * starved peers' defer_finish AG acquires into rc=-110 shutdowns.
	 * Entry locks FIRST, then AG grants under a still-clean transaction.
	 *
	 * (D-501, design-consult ruled): only the AGs this rename WILL
	 * demand past a non-restartable boundary are mandatory — an
	 * existing target_ip's home AG (in-trans iunlink add, and difree
	 * when its last link drops) and a whiteout wip's home AG (in-trans
	 * iunlink remove).  The other participants' home AGs (src/target
	 * dir, src_ip) are optional insurance: preacquiring them blocking
	 * falsely coupled the hot dir's EX with its home AG and serialized
	 * the whole cluster on ~600ms AG handoffs per no-AG rename
	 * (dlm_fairness 0/32).  A miss on those now just proceeds.
	 */
	{
		struct xfs_inode	*mand_ips[2];
		int			num_mand = 0;

		if (target_ip)
			mand_ips[num_mand++] = target_ip;
		if (du_wip.ip)
			mand_ips[num_mand++] = du_wip.ip;
		error = mxfs_trans_preacquire_inode_ags(tp, inodes,
				num_inodes, mand_ips, num_mand);
	}
	if (error == -EAGAIN) {
		/*
		 * (-488 fourth face): the preacquire's bounded ILOCK
		 * handoff budget ran out under sustained AG contention.  The
		 * transaction is CLEAN and the helper returned with our locks
		 * retaken, so this is the same benign unwind as the quota
		 * retry below: cancel, unlock, jittered pause (holding
		 * nothing), and retry the whole rename on fresh state.
		 *
		 * (design-consult ruled, shape B): the retry is UNBOUNDED —
		 * contention exhaustion must never surface to userspace as an
		 * errno (the old 3-try cap converted it to a spurious
		 * -ETIMEDOUT under a 32-way same-dir rename storm).  The
		 * inner 8-handoff budget is a batching boundary, not a
		 * failure threshold.  Backoff is per-node randomized and
		 * capped; genuine cluster failure exits via the shutdown
		 * check (a real DLM timeout inside the handoff's blocking
		 * acquire returns its own error, not -EAGAIN, and still
		 * propagates below).
		 */
		++preacq_tries;
		mxfs_probe_ratelimited(
		    "mxfs: P290-RENAME-CLEANRETRY src_dp=%llu ip=%llu try=%d rc=%d\n",
		    (unsigned long long)src_dp->i_ino,
		    (unsigned long long)src_ip->i_ino,
		    preacq_tries, error);
		xfs_trans_cancel(tp);
		xfs_iunlock_rename(inodes, num_inodes);
		if (xfs_is_shutdown(mp)) {
			error = -EIO;
			goto out_tgt_ppargs;
		}
		msleep(10 + get_random_u32_below(
				40 * umin(preacq_tries, 10)));
		goto retry;
	}
	if (error)
		goto out_trans_cancel;

	error = xfs_projid_differ(target_dp, src_ip);
	if (error)
		goto out_trans_cancel;

	/*
	 * MODIFY-side acquire cold-read for rename (mirror of the
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
	 * (2/tcp): pre-dirty source/target-name revalidation — the rename
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
		 * (D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361, design review
		 * Design-consult ruling) — FULL target-expectation preflight for the
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

		/* P217 cookie: the preflight just proved the names
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
	 *  — D-DIRENT-INODE-TYPE-MISMATCH PRODUCER PROBE
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
				mxfs_probe("mxfs: P206-RENAME-FTYPE-STALE src_ip=%llu name=\"%.*s\" write_ft=%u live_ft=%u live_mode=0%o gen=%u stale=%d dlm_mode=%d src_is_directory=%d src_dp=%llu target_dp=%llu reval=%d comm=%s — dirent ftype snapshotted before the ILOCK contradicts the inode's post-reload type\n",
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
					mxfs_probe("mxfs: P206-EXCHANGE-FTYPE-STALE target_ip=%llu name=\"%.*s\" write_ft=%u live_ft=%u live_mode=0%o gen=%u stale=%d reval=%d comm=%s\n",
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
	 * PUBLISH-BEFORE-NOTIFY — rename is the worst lost-update case
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
	 * P217-RENAME-DIRTYCANCEL (design review item: "instrument the exact first
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
			pr_warn("mxfs: P217-RENAME-DIRTYCANCEL rc=%d src_dp=%llu tgt_dp=%llu src=\"%.*s\" tgt=\"%.*s\" armed=%d pre[iv=%llu bytes=%u fmt=%d dgen=%llu ve=%u] now[iv=%llu bytes=%lld fmt=%d dgen=%llu ve=%u] exch=%d wip=%d comm=%s — dirty cancel imminent (0x8 shutdown); cookie names the class\n",
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
				(long long)src_dp->i_df.if_bytes,
				src_dp->i_df.if_format,
				(unsigned long long)src_dp->i_dlm_dir_gen,
				src_dp->i_dlm_dir_valid_epoch,
				(flags & RENAME_EXCHANGE) ? 1 : 0,
				du_wip.ip ? 1 : 0, current->comm);
	}
	xfs_trans_cancel(tp);
out_unlock:
	/*
	 * make each SHORTFORM rename-dir's just-committed change durable
	 * on its on-disk inode cluster (mirror xfs_create / xfs_remove).  Rename
	 * is the worst lost-update case: the source-dir's REMOVAL of the old name
	 * must be destaged, else a peer / eviction-ring re-read cold-reads the
	 * stale cluster and durably RESURRECTS the renamed-away dirent (the
	 * dlm_fairness `mv n_rX n_rX.done` leftover).  ILOCK dropped below;
	 * success path only; !self_created keeps rsync's node-private dirs free.
	 *
	 * PROVEN FIX: pin each dir's DLM-EX grant across
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
		/* gate shared with create/remove — mxfs_dir_op_needs_publish
		 * (dirop_virgin_skip). */
		extern bool mxfs_dir_op_needs_publish(struct xfs_inode *);
		bool src_pin = !error && src_dp &&
			mxfs_dir_op_needs_publish(src_dp);
		bool tgt_pin = !error && target_dp && target_dp != src_dp &&
			mxfs_dir_op_needs_publish(target_dp);

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

/*
 * (design-consult ruling 2, Q2) — CANONICAL EQUALITY ORACLE.
 *
 * Answers ONE question: is the home (platter) dinode canonically equal to the
 * image this inode currently owes?  If it is, our logged changes are already
 * present at home and the publication obligation is discharged in fact, however
 * the bookkeeping reads.
 *
 * WHY THE EXISTING TEST IS NOT ENOUGH.  P-RELOAD-IDENTICAL compares di_gen,
 * mode, format, size, nextents and di_changecount == i_version.  That is a good
 * freshness heuristic and a bad durability proof: equal nextents is not equal
 * extents, and equal size is not equal shortform bytes — the P175-SFCONTENT-
 * UNLANDED probe exists precisely because "header fields match but SHORTFORM
 * CONTENT differs from platter".  nlink is not compared at all.
 *
 * FAIL CLOSED IS THE WHOLE POINT.  A false "equal" here would close a
 * publication obligation that is NOT satisfied — silent, cluster-wide metadata
 * loss, which is strictly worse than the wedge this work is removing.  So this
 * returns true ONLY for cases it can compare in full, and false for everything
 * else, INCLUDING every case it does not understand.  EXTENTS and BTREE forks
 * are deliberately refused: comparing them faithfully means re-encoding the
 * in-core extent list, and an approximate comparison of a fork is exactly the
 * mistake being corrected here.
 *
 * TELEMETRY ONLY at this stage.  Nothing acts on the verdict yet; it is
 * measured against reality first (exact-match must say equal, injected
 * single-field mismatches must say not-equal) before any close path consumes
 * it.  See the ruling's falsifiers: closed_as_identical => canonical(home) ==
 * canonical(owed).
 */
static bool
mxfs_home_equals_owed(
	struct xfs_inode	*ip,
	struct xfs_dinode	*home,
	const char		**why)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct inode		*inode = VFS_I(ip);
	struct xfs_ifork	*dfp = &ip->i_df;

	*why = "?";
	if (!home || home->di_magic != cpu_to_be16(MXFS_DINODE_MAGIC))
		return (*why = "no-home", false);
	if (home->di_version < 3)
		return (*why = "v2-dinode", false);

	/* Incarnation first: everything below is meaningless across a reuse. */
	if (be32_to_cpu(home->di_gen) != inode->i_generation)
		return (*why = "gen", false);

	/*
	 * The logical version.  di_changecount is bumped once per CORE-logging
	 * transaction on MXFS (the forced bump), so equality here means
	 * home has seen the same number of logical modifications we have.
	 */
	if (be64_to_cpu(home->di_changecount) != inode_peek_iversion(inode))
		return (*why = "changecount", false);

	if (be16_to_cpu(home->di_mode) != inode->i_mode)
		return (*why = "mode", false);
	if (be32_to_cpu(home->di_nlink) != inode->i_nlink)
		return (*why = "nlink", false);	/* NOT in the legacy test */
	if (be32_to_cpu(home->di_uid) != i_uid_read(inode))
		return (*why = "uid", false);
	if (be32_to_cpu(home->di_gid) != i_gid_read(inode))
		return (*why = "gid", false);
	if (be64_to_cpu(home->di_size) != (uint64_t)ip->i_disk_size)
		return (*why = "size", false);
	if (be64_to_cpu(home->di_nblocks) != ip->i_nblocks)
		return (*why = "nblocks", false);
	if (be32_to_cpu(home->di_extsize) != ip->i_extsize)
		return (*why = "extsize", false);
	if (be16_to_cpu(home->di_flags) != ip->i_diflags)
		return (*why = "flags", false);
	if (be64_to_cpu(home->di_flags2) != ip->i_diflags2)
		return (*why = "flags2", false);
	if (home->di_forkoff != ip->i_forkoff)
		return (*why = "forkoff", false);
	if (home->di_format != xfs_ifork_format(dfp))
		return (*why = "dformat", false);

	/*
	 * The literal area.  Only LOCAL is compared in full here; that is the
	 * shape the known counterexample (P175 shortform content) lives in.
	 * Anything else is refused rather than guessed at.
	 */
	if (xfs_ifork_format(dfp) != XFS_DINODE_FMT_LOCAL)
		return (*why = "dfork-not-local", false);
	if (dfp->if_bytes < 0 ||
	    dfp->if_bytes > XFS_DFORK_DSIZE(home, mp))
		return (*why = "dfork-size", false);
	if (dfp->if_bytes > 0 &&
	    (!dfp->if_data ||
	     memcmp(XFS_DFORK_PTR(home, XFS_DATA_FORK), dfp->if_data,
		    dfp->if_bytes)))
		return (*why = "dfork-bytes", false);

	/* An attr fork we cannot compare in full is a refusal, not a pass. */
	if (ip->i_forkoff) {
		struct xfs_ifork *afp = &ip->i_af;

		if (afp->if_format != XFS_DINODE_FMT_LOCAL)
			return (*why = "afork-not-local", false);
		if (home->di_aformat != afp->if_format)
			return (*why = "aformat", false);
		if (afp->if_bytes < 0 ||
		    afp->if_bytes > XFS_DFORK_ASIZE(home, mp))
			return (*why = "afork-size", false);
		if (afp->if_bytes > 0 &&
		    (!afp->if_data ||
		     memcmp(XFS_DFORK_PTR(home, XFS_ATTR_FORK), afp->if_data,
			    afp->if_bytes)))
			return (*why = "afork-bytes", false);
	}

	*why = "equal";
	return true;
}

/*
 * 0.75.46: publish the in-core forks of a multi-node flush.
 *
 * xfs_iflush_fork copies a fork into the staged dinode only when that fork
 * was logged (XFS_ILOG_DEXT / DDATA / DBROOT and the attr equivalents), on
 * the upstream premise that the cluster buffer already holds the fork's last
 * flushed image.  MXFS breaks that premise: a reload that keeps the cluster
 * buffer PROTECTED (P91-RELOAD-PROTECT: the buffer carries this node's
 * uncheckpointed changes to other inodes of the cluster) adopts the peer's
 * dinode from a private platter read and leaves the buffer slot as it was.
 * A core-only flush of that inode then writes the adopted di_nextents /
 * di_size over the slot's OLD fork bytes, and the platter holds an extents
 * inode whose records belong to a previous life of the file.
 *
 * Proven on the two-node TCP rig (D-0920, lap s527f, inode 8388909): the
 * slot held the create-time image, the peer wrote one extent, this node's
 * reload adopted it privately, an append inside that block dirtied the core
 * only, and the flush staged nextents=1 over sixteen zero bytes; the peer's
 * next platter read failed extent validation and the file read empty.
 *
 * This re-encodes each in-core fork exactly the way the logged copy would
 * (xfs_iextents_copy / xfs_bmbt_to_bmdr / the local bytes) and, when the
 * staged bytes differ on an UNLOGGED fork, writes the in-core encoding into
 * the staged image.  The in-core fork is the truth for the node holding the
 * inode's grant, so this is exactly the copy the logged case performs and is
 * a no-op wherever upstream's premise holds.  Each repair is counted and
 * reported as P-IFLUSH-FORK-STALE.  A mismatch on a logged fork cannot
 * happen (the copy just ran) and is reported as such.  Delalloc-only extent
 * forks are skipped: they have nothing on disk yet.
 */
static void
mxfs_iflush_fork_publish(
	struct xfs_inode	*ip,
	struct xfs_dinode	*dip,
	struct xfs_inode_log_item *iip,
	struct xfs_buf		*bp)
{
	static atomic_t		stale_total = ATOMIC_INIT(0);
	static const short	brootflag[2] = { XFS_ILOG_DBROOT, XFS_ILOG_ABROOT };
	static const short	dataflag[2] = { XFS_ILOG_DDATA, XFS_ILOG_ADATA };
	static const short	extflag[2] = { XFS_ILOG_DEXT, XFS_ILOG_AEXT };
	struct xfs_mount	*mp = ip->i_mount;
	int			whichfork;

	if (!iip)
		return;
	for (whichfork = XFS_DATA_FORK; whichfork <= XFS_ATTR_FORK; whichfork++) {
		struct xfs_ifork	*ifp;
		char			*cp;
		void			*want = NULL;
		void			*scratch = NULL;
		int			fsize, wlen = 0, logged, zero_recs = 0, i;

		if (whichfork == XFS_ATTR_FORK && !xfs_inode_has_attr_fork(ip))
			break;
		ifp = xfs_ifork_ptr(ip, whichfork);
		if (!ifp)
			continue;
		cp = XFS_DFORK_PTR(dip, whichfork);
		fsize = XFS_DFORK_SIZE(dip, mp, whichfork);
		switch (ifp->if_format) {
		case XFS_DINODE_FMT_LOCAL:
			if (ifp->if_bytes <= 0 || !ifp->if_data)
				continue;
			logged = iip->ili_fields & dataflag[whichfork];
			want = ifp->if_data;
			wlen = ifp->if_bytes;
			break;
		case XFS_DINODE_FMT_EXTENTS:
			if (ifp->if_nextents == 0 || ifp->if_bytes <= 0)
				continue;
			logged = iip->ili_fields & extflag[whichfork];
			wlen = ifp->if_nextents * sizeof(struct xfs_bmbt_rec);
			if (wlen > fsize)
				wlen = fsize;
			scratch = kmalloc(wlen, GFP_NOFS | __GFP_NOWARN);
			if (!scratch)
				continue;
			wlen = xfs_iextents_copy(ip, scratch, whichfork);
			want = scratch;
			break;
		case XFS_DINODE_FMT_BTREE:
			if (ifp->if_broot_bytes <= 0 || !ifp->if_broot)
				continue;
			logged = iip->ili_fields & brootflag[whichfork];
			scratch = kzalloc(fsize, GFP_NOFS | __GFP_NOWARN);
			if (!scratch)
				continue;
			xfs_bmbt_to_bmdr(mp, ifp->if_broot, ifp->if_broot_bytes,
					 scratch, fsize);
			wlen = xfs_bmap_bmdr_space(ifp->if_broot);
			if (wlen > fsize)
				wlen = fsize;
			want = scratch;
			break;
		default:
			continue;
		}
		if (wlen <= 0 || wlen > fsize || memcmp(cp, want, wlen) == 0) {
			kfree(scratch);
			continue;
		}
		if (ifp->if_format == XFS_DINODE_FMT_EXTENTS) {
			for (i = 0; i + (int)sizeof(struct xfs_bmbt_rec) <= wlen;
			     i += sizeof(struct xfs_bmbt_rec)) {
				uint64_t *r = (uint64_t *)(cp + i);

				if (r[0] == 0 && r[1] == 0)
					zero_recs++;
			}
		}
		atomic_inc(&stale_total);
		if (!logged)
			memcpy(cp, want, wlen);
		mxfs_probe_ratelimited("mxfs: P-IFLUSH-FORK-STALE ino=%llu fork=%d fmt=%d nextents=%llu size=%lld bytes=%d ili_fields=0x%x logged=%d zero_recs=%d daddr=%lld pin=%d dlm_mode=%u total=%d comm=%s — staged fork differed from the in-core fork%s\n",
			(unsigned long long)ip->i_ino, whichfork,
			ifp->if_format,
			(unsigned long long)ifp->if_nextents,
			(long long)ip->i_disk_size, wlen, iip->ili_fields,
			logged ? 1 : 0, zero_recs,
			(long long)bp->b_maps[0].bm_bn,
			atomic_read(&ip->i_pincount), ip->i_dlm_mode,
			atomic_read(&stale_total), current->comm,
			logged ? " AFTER the logged copy" :
			 "; in-core fork written into the staged image");
		kfree(scratch);
	}
}

static int
xfs_iflush(
	struct xfs_inode	*ip,
	struct xfs_buf		*bp)
{
	struct xfs_perag	*p55c_pag = NULL;	/* publication-write gate held */
	uint64_t		p55c_claim_epoch = 0;	/* FREE claim to mint on success */
	struct xfs_inode_log_item *iip = ip->i_itemp;
	struct xfs_dinode	*dip;
	struct xfs_mount	*mp = ip->i_mount;
	int			error;
	/*
	 * D3 residual, wiring step 2 (completion):
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
	 * INSTRUMENTED DETECTOR (P-IRESURRECT): the bnobt double-free
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
	    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC)) {
		struct inode *vinode = VFS_I(ip);
		uint16_t disk_mode = be16_to_cpu(dip->di_mode);
		uint32_t disk_gen = be32_to_cpu(dip->di_gen);
		uint32_t disk_nlink = be32_to_cpu(dip->di_nlink);

		if (disk_mode != vinode->i_mode || disk_gen != vinode->i_generation ||
		    disk_nlink != vinode->i_nlink) {
			static atomic_t irn = ATOMIC_INIT(0);
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
			    atomic_inc_return(&irn) <= 4000)
				mxfs_probe("mxfs: P-IRESURRECT ino=%llu incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u incore_nlink=%u disk_nlink=%u inew=%d istale_caw=%d dlm_mode=%u dlm_state=%u comm=%s realns=%llu\n",
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
	if (dip->di_magic != cpu_to_be16(MXFS_DINODE_MAGIC) ||
	    XFS_TEST_ERROR(mp, XFS_ERRTAG_IFLUSH_1)) {
		xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
			"%s: Bad inode %llu magic number 0x%x, ptr "PTR_FMT,
			__func__, ip->i_ino, be16_to_cpu(dip->di_magic), dip);
		/*
		 * P20-IFLUSH-FORENSIC (instrumented): a bad-magic cluster buffer at
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
			mxfs_probe("mxfs: P20-IFLUSH-FORENSIC ino=%llu daddr=%llu len=%d bflags=0x%x li_empty=%d pin=%d disk_differs=%d imap_blk=%llu boff=%u\n",
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
		 * TORN-SHORTFORM-DIR FLUSH BARRIER (instrumented,
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

				mxfs_probe("mxfs: P22-SFTORN-SKIP ino=%llu if_bytes=%lld dlm_mode=%u inew=%d istale_caw=%d dirty_seq=%llu ex_grant_seq=%llu ili_fields=0x%x flushiter=%d hdr=[%02x %02x %02x %02x %02x %02x %02x %02x] comm=%s\n",
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
			 * ROOT FIX — run13/run15 PROVEN
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
	 * SF-DIR SIZE-DESYNC TRIPWIRE (instrumented instrument +
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
			mxfs_probe("mxfs: P14-SFSIZE-DESYNC ino=%llu if_bytes=%lld disk_size=%lld ili_fields=0x%x dlm_mode=%u istale_caw=%d comm=%s realns=%llu\n",
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
	 * instrumented GUARD (the P-IRESURRECT detector, now acting):
	 * do NOT resurrect a peer-reincarnated inode.  If the on-disk dinode is a
	 * DIFFERENT incarnation than our in-core inode (disk di_gen != in-core
	 * i_generation), the disk copy is the authoritative newer life (a peer
	 * freed our inode and re-allocated that inode number, bumping the gen).
	 * Our in-core image is a stale ghost; copying it over the disk would
	 * RESURRECT the dead inode, double-allocating its blocks/inode-record and
	 * later faulting xfs_dialloc with EFSCORRUPTED (badmagic) -> FS shutdown
	 * (PROVEN P-IRESURRECT comm=xfsaild incore_mode=0100644
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
	 * REFUTED: they skipped legitimate new-inode first flushes
	 * (disk_gen=0, INEW already cleared by the async xfsaild flush) -> the new
	 * file was never persisted -> cross_visibility "cannot see" + AIL stall.
	 * !INEW + valid magic are kept as belt-and-suspenders.
	 */
	{
		/*
		 * (design-consult design #4) — CO-RESIDENT
		 * COMMITTED-CHANGE FLUSH.  The /guards below DISCARD any
		 * non-EX dirty inode on the theory "non-EX -> clean-or-ghost, never a
		 * pending legit write" (invariant #1 drains before release).  Instrumented
		 * PROVEN FALSE for a CO-RESIDENT (tcp_dlm_scaling "drained got=1"):
		 * when this node flushes dir A's 4 KiB inode cluster (release flush or
		 * mxfs_inode_cluster_durable), the cluster also holds a DIFFERENT dir B
		 * that this node modified+committed under a prior EX tenure and then
		 * DEMOTED to PR (the demote's drain flushed A's cluster, not B's own).
		 * B reaches xfs_iflush still in_ail at i_dlm_mode=PR; P119 marks it
		 * CLEAN without writing -> B's committed dirent removal is LOST -> the
		 * stale on-disk dirent survives -> leak (PROVEN /55 stack: P119
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
			dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
			be16_to_cpu(dip->di_mode) != 0 &&
			(be16_to_cpu(dip->di_mode) & S_IFMT) ==
				(VFS_I(ip)->i_mode & S_IFMT) &&
			be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
			ip->i_itemp &&
			test_bit(XFS_LI_IN_AIL,
				 &ip->i_itemp->ili_item.li_flags);
		/*
		 * (D-FOSSIL-NEXT-UNLINKED-IGET-LOGSAME-388 root; design-consult
		 * ruling F1) — PUBLICATION-OBLIGATION FLUSH AT PR.  Measured chain
		 * (test10 ino 130023711 / test7 ino 92277034, identical): this
		 * node's unlink committed while the inode's DLM mode was PR (a
		 * release drain had stripped EX->PR and the holder re-acquired
		 * mid-drain, P15-REL-ABORT); the release was correctly DEFERRED on
		 * the open obligation (P244); then xfsaild reached THIS gate first
		 * and P119 marked the committed nlink=0 conversion CLEAN WITHOUT
		 * WRITING (in_ail=1, incore_nlink=0, disk_nlink=1).  The release
		 * worker's converter (P245) then found a clean item and wrote
		 * nothing, the reload "closed" the ledger by keeping the newer
		 * in-core (P3-REFUSE-OLDER-DISK + P177 identical=1), and the AGI
		 * unlinked list was left naming a home dinode that reads LINKED
		 * forever: P88-PUBOB-UNREPAIRED x60/node, P87-PUBLISH-DEFER-
		 * EXHAUSTED (4s per AG release -> late dirent visibility), and the
		 * fossil di_next_unlinked on reuse.
		 *
		 * The P55 exclusion argument applies verbatim: while we hold PR no
		 * peer holds EX and no peer write is in flight, so our committed
		 * in-core image is authoritative and clobbers nothing.  Narrowed
		 * per the ruling to an OWNED obligation — MXFS_IF_PUBOB is armed
		 * only by this node's own xfs_iunlink insert and cleared only on a
		 * confirmed home write / list removal — with nlink==0, the same
		 * incarnation, a live same-type disk slot, the item in the AIL and
		 * no write-poison.  The release terminal gate (P244) keeps PR until
		 * the buffer write COMPLETES (durable_seq advances only from
		 * xfs_iflush_finish), so the write is fenced through completion.
		 * The REFUTED keep-dirty forms (0.19.36/37) kept the item dirty
		 * with NO writer; this WRITES it — xfsaild is the sanctioned
		 * converter while the authority is still held.
		 */
		{
			bool mxfs_pubob_pr_flush =
				mp->m_mxfs_dlm &&
				!mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
				!mxfs_cores_commit_flush &&
				xfs_iflags_test(ip, MXFS_IF_PUBOB) &&
				VFS_I(ip)->i_nlink == 0 &&
				ip->i_dlm_mode == MXFS_LOCK_PR &&
				!ip->i_mxfs_dead_incarn_gen &&
				dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
				be16_to_cpu(dip->di_mode) != 0 &&
				(be16_to_cpu(dip->di_mode) & S_IFMT) ==
					(VFS_I(ip)->i_mode & S_IFMT) &&
				be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
				ip->i_itemp &&
				test_bit(XFS_LI_IN_AIL,
					 &ip->i_itemp->ili_item.li_flags);
			/* fault injection (see pubob_launder_inject): let
			 * the next N owned-PUBOB PR conversions fall through to the
			 * old P119 launder so the F2 repair writer is exercised. */
			if (mxfs_pubob_pr_flush) {
				extern int mxfs_pubob_launder_inject;
				int inj = READ_ONCE(mxfs_pubob_launder_inject);

				/* Only a flush that would otherwise be laundered by
				 * P119 counts — a RELFLUSH-sanctioned converter flush
				 * bypasses P119 regardless (measured test10: the
				 * repair's own flush consumed a count, no effect). */
				if (unlikely(inj > 0) &&
				    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
				    ip->i_dlm_demoter == NULL) {
					WRITE_ONCE(mxfs_pubob_launder_inject, inj - 1);
					mxfs_probe("mxfs: P55B-INJECT-LAUNDER ino=%llu i_dlm_mode=%u pend=%llu dur=%llu left=%d — fault-injected launder of an owned PUBOB conversion\n",
						(unsigned long long)ip->i_ino,
						(unsigned)ip->i_dlm_mode,
						(unsigned long long)ip->i_mxfs_pub_pending_seq,
						(unsigned long long)ip->i_mxfs_pub_durable_seq,
						inj - 1);
					mxfs_pubob_pr_flush = false;
				}
			}
			if (mxfs_pubob_pr_flush) {
				static atomic_t ppf = ATOMIC_INIT(0);

				if (atomic_inc_return(&ppf) <= 4000)
					mxfs_probe("mxfs: P55B-PUBOB-PR-FLUSH ino=%llu i_dlm_mode=%u mode=0%o gen=%u disk_nlink=%u pend=%llu dur=%llu comm=%s — flushing PR-held committed unlink conversion (not discarding)\n",
						(unsigned long long)ip->i_ino,
						(unsigned)ip->i_dlm_mode,
						VFS_I(ip)->i_mode,
						VFS_I(ip)->i_generation,
						be32_to_cpu(dip->di_nlink),
						(unsigned long long)ip->i_mxfs_pub_pending_seq,
						(unsigned long long)ip->i_mxfs_pub_durable_seq,
						current->comm);
				mxfs_cores_commit_flush = true;
			}
		}
		if (mxfs_cores_commit_flush) {
			static atomic_t ccf = ATOMIC_INIT(0);
			if (atomic_inc_return(&ccf) <= 4000)
				mxfs_probe("mxfs: P55-CORESIDENT-COMMIT-FLUSH ino=%llu i_dlm_mode=%u mode=0%o gen=%u in_ail=1 comm=%s — flushing PR-held committed change (not discarding)\n",
					(unsigned long long)ip->i_ino,
					(unsigned)ip->i_dlm_mode,
					VFS_I(ip)->i_mode,
					VFS_I(ip)->i_generation,
					current->comm);
		}
		/*
		 * (design review design-consult validated) — DLM-OWNERSHIP DISCRIMINATOR.
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
		 * Writing it would either RESURRECT a peer-freed inode (
		 * corruption: xfs_dialloc badmagic -> EFSCORRUPTED -> shutdown) or
		 * CLOBBER a peer's live incarnation (the cross_visibility barrier
		 * lost-update: ino=133 .mxfs_test/test_rename_visibility, a LIVE
		 * dir this node owns, was being skipped by the old gen heuristic).
		 *
		 * This REPLACES the di_gen comparison used.  XFS bumps
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
	 *  (instrumented, PROVEN via P-SFDIR-REVERT ino=152
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
	/*
	 * (D-0351, FREE-PUBLISH invariant; design-consult ruling ccmemory
	 * docs/rulings/free-publish-invariant-d0351.md).
	 * P55C — a COMMITTED FREE whose home dinode still reads LIVE.  The
	 * generic P119 guard below discards this flush (a freed inode's
	 * per-inode grant is NL/stripped or it is cluster-routed), which is
	 * exactly how s430's test1 published its inobt free with a live
	 * platter dinode and shut test2 down.  Classify the platter image
	 * against the obligation {gen, epoch}:
	 *   mode=0, gen==ob.gen      : already published — discharge, skip;
	 *   mode!=0, gen==ob.gen-1   : the exact incarnation we freed — WRITE
	 *                              it, sanctioned by (a) the release
	 *                              audit's retiring token (RELFLUSH under
	 *                              pag_dlm_demoting, after its own FUA
	 *                              verify) or (b) the publication-write
	 *                              gate on the SAME uninterrupted AG EX
	 *                              tenure the ifree committed under;
	 *                              otherwise keep the item DIRTY
	 *                              (-EAGAIN, nothing consumed): laundering
	 *                              would let reclaim take the only copy;
	 *   any other gen            : not our predecessor (a peer's later
	 *                              incarnation, or a chunk re-init) —
	 *                              NEVER write; neutralize + discharge.
	 * The ifree is in our journal by construction here (in-AIL items only
	 * reach a flush after their log write completed).
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    !mxfs_cores_commit_flush && READ_ONCE(ip->i_mxfs_freeob) == 2 &&
	    xfs_iflags_test(ip, MXFS_IF_PUBOB) && VFS_I(ip)->i_mode == 0 &&
	    VFS_I(ip)->i_nlink == 0 &&
	    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC)) {
		uint8_t		okind = 0;
		uint32_t	ogen = 0;
		uint64_t	oepoch = 0;
		uint16_t	ochain = 0;
		uint32_t	dgen = be32_to_cpu(dip->di_gen);
		uint16_t	dmode = be16_to_cpu(dip->di_mode);
		bool		in_ail = ip->i_itemp &&
				test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags);

		/*
		 * (s439 board): "home" here was the BUFFER slot, which
		 * after this node's own copy-in holds OUR staged free image —
		 * not the platter.  A staged image whose completion was
		 * re-armed (stale PUB_SKIPPED) or dropped then read back as
		 * "free image already at home" and the obligation was settled
		 * and discharged from bytes that may never have landed.
		 *
		 * 0.39.6 gated the platter read on flush_seq != durable_seq;
		 * that is NOT a sufficient detector (design-consult review, 0.39.9):
		 * every drop path rolls flush_seq back to durable_seq while the
		 * buffer keeps the staged mode-0 bytes, so a dropped claimed
		 * write followed by a re-push would still have read the buffer
		 * as "free at home".  The classification is therefore ALWAYS
		 * taken from a coherent raw platter read (a private bounce
		 * buffer, never the xfs buffer cache; the same read the dialloc
		 * validation trusts).  The buffer is locked here, so no write of
		 * this cluster is in flight and none can be submitted until the
		 * copy-in returns; peers are excluded by the AG tenure the FREE
		 * obligation holds.  A failed or invalid read is DENIED (dirty
		 * kept, strike), never a verdict.
		 */
		{
			extern uint16_t mxfs_dbg_disk_di_mode_coherent(
					struct xfs_mount *, xfs_ino_t, uint32_t *);
			uint32_t	pgen = 0;
			uint16_t	pmode = mxfs_dbg_disk_di_mode_coherent(mp,
							ip->i_ino, &pgen);
			static atomic_t p55h_n = ATOMIC_INIT(0);

			if (pmode == 0xFFFF) {
				mxfs_pubob_free_strike(mp, ip);
				if (atomic_inc_return(&p55h_n) <= 500)
					mxfs_probe("mxfs: P55C-HOME-READ-FAIL ino=%llu buf_mode=0%o buf_gen=%u flush=%llu dur=%llu — platter read failed while an own staged image is unlanded; keeping the free image dirty\n",
						(unsigned long long)ip->i_ino, dmode, dgen,
						(unsigned long long)ip->i_mxfs_pub_flush_seq,
						(unsigned long long)ip->i_mxfs_pub_durable_seq);
				return -EAGAIN;
			}
			if (pmode != dmode || pgen != dgen) {
				if (atomic_inc_return(&p55h_n) <= 500)
					mxfs_probe("mxfs: P55C-HOME-PLATTER ino=%llu buf_mode=0%o buf_gen=%u platter_mode=0%o platter_gen=%u flush=%llu dur=%llu — buffer slot is this node's unlanded staged image; classifying on the platter\n",
						(unsigned long long)ip->i_ino, dmode, dgen,
						pmode, pgen,
						(unsigned long long)ip->i_mxfs_pub_flush_seq,
						(unsigned long long)ip->i_mxfs_pub_durable_seq);
				dmode = pmode;
				dgen = pgen;
			}
		}

		if (mxfs_pubob_lookup(mp, ip->i_ino, &okind, &ogen, &oepoch,
				      &ochain) &&
		    okind == 2 /* MXFS_PUBOB_FREE */) {
			static atomic_t p55c_n = ATOMIC_INIT(0);

			/*
			 * (s431 board: 51 false P55C-FREE-FOREIGN, all
			 * disk_mode=00): i_generation is RANDOM at allocation and
			 * ++ at free, so a short-lived incarnation whose live image
			 * never reached the platter leaves mode=0 at the
			 * PRE-allocation gen.  The invariant is about MODE — a
			 * free platter dinode satisfies FREE-PUBLISH whatever its
			 * gen (ours, the older free, or a peer's later free).
			 */
			if (dmode == 0) {
				if (atomic_inc_return(&p55c_n) <= 2000)
					mxfs_probe("mxfs: P55C-FREE-HOME ino=%llu gen=%u disk_gen=%u — free image already at home%s; discharging\n",
						(unsigned long long)ip->i_ino, ogen, dgen,
						dgen == ogen ? "" : " (older/other free image)");
				/* (0.38.4): settle the freed incarnation's
				 * publication ledger by equivalence BEFORE the
				 * discharge (the predicate needs the live obligation);
				 * otherwise flush_out marks it fence-abandoned and
				 * the unlinked inode's evict shuts the node down. */
				mxfs_pubob_settle_home_free(mp, ip, "iflush");
				mxfs_pubob_discharge(mp, ip, "home-free");
				xfs_iflags_set(ip, XFS_ISTALE_CAW);
				error = 0;
				goto flush_out;
			} else if (dmode != 0 &&
				   (dgen == (uint32_t)(ogen - 1u) || ochain)) {
				/*
				 * (D-0351 chain, design-consult ruling): a CHAINED
				 * free (this node re-allocated and re-freed the
				 * number under one uninterrupted tenure) may find
				 * an earlier life of its own at home at any gen —
				 * s433: 164 such verdicts misread as FOREIGN, the
				 * live image left under an inobt-free bit.  The
				 * tenure sanction below IS the ownership proof:
				 * no peer can allocate without the AG EX, and the
				 * release audit publishes or fails closed before
				 * any unlock.  No sanction -> DENIED (never
				 * FOREIGN) so the recovery worker decides under a
				 * fresh EX.
				 */
				struct xfs_perag *fpag = in_ail ? xfs_perag_get(mp,
						XFS_INO_TO_AGNO(mp, ip->i_ino)) : NULL;
				const char *how = NULL;

				if (fpag && xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
				    READ_ONCE(fpag->pag_dlm_demoting) &&
				    READ_ONCE(fpag->pag_mxfs_rel_epoch) != 0) {
					how = "retiring-token";
				} else if (fpag && mxfs_ag_pubwrite_begin(fpag, oepoch)) {
					how = "tenure";
					p55c_pag = fpag;	/* released at flush_out */
					fpag = NULL;
				}
				if (fpag)
					xfs_perag_put(fpag);
				if (how) {
					if (atomic_inc_return(&p55c_n) <= 2000)
						mxfs_probe("mxfs: P55C-FREE-%s ino=%llu gen=%u disk_gen=%u disk_mode=0%o epoch=%llu chain=%u via=%s comm=%s — writing the committed free image (FREE-PUBLISH)\n",
							dgen == (uint32_t)(ogen - 1u) ? "FLUSH" : "CHAIN",
							(unsigned long long)ip->i_ino, ogen,
							dgen, dmode,
							(unsigned long long)oepoch, ochain, how,
							current->comm);
					mxfs_cores_commit_flush = true;
					p55c_claim_epoch = oepoch;
				} else {
					mxfs_pubob_free_strike(mp, ip);
					if (atomic_inc_return(&p55c_n) <= 2000)
						mxfs_probe("mxfs: P55C-FREE-DENIED ino=%llu gen=%u disk_gen=%u epoch=%llu ag_epoch=%llu chain=%u in_ail=%d strikes=%u comm=%s — no tenure sanction; keeping the free image dirty (never laundered)\n",
							(unsigned long long)ip->i_ino, ogen,
							dgen, (unsigned long long)oepoch,
							(unsigned long long)mxfs_ag_grant_epoch_of(mp, ip->i_ino),
							ochain,
							in_ail ? 1 : 0,
							(unsigned)READ_ONCE(ip->i_mxfs_freeob_strikes),
							current->comm);
					return -EAGAIN;
				}
			} else {
				mxfs_probe("mxfs: P55C-FREE-FOREIGN ino=%llu gen=%u disk_gen=%u disk_mode=0%o — home dinode is NOT the incarnation this node freed (FREE-PUBLISH was crossed earlier); never writing this shell; discharging\n",
					(unsigned long long)ip->i_ino, ogen, dgen, dmode);
				ip->i_mxfs_dead_incarn_gen = dgen ? dgen : 1;
				mxfs_pubob_discharge(mp, ip, "foreign");
				xfs_iflags_set(ip, XFS_ISTALE_CAW);
				error = 0;
				goto flush_out;
			}
		}
	}
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
	    ip->i_dlm_mode != MXFS_LOCK_EX &&
	    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    (ip->i_dlm_routed_iclus || ip->i_dlm_demoter == NULL) &&
	    !mxfs_cores_commit_flush) {
		static atomic_t irsk = ATOMIC_INIT(0);
		if (atomic_inc_return(&irsk) <= 4000)
			mxfs_probe("mxfs: P119-NONEX-FLUSH-SKIP ino=%llu i_dlm_mode=%u incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u incore_nlink=%u disk_nlink=%u exh=%d prh=%d in_ail=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				(unsigned)ip->i_dlm_mode,
				VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
				VFS_I(ip)->i_generation, be32_to_cpu(dip->di_gen),
				VFS_I(ip)->i_nlink, be32_to_cpu(dip->di_nlink),
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
				current->comm);
		/* instrumented: one-shot stack dump for a DIR skip so we can name the
		 * exact caller whose committed dir change is being discarded (the
		 * residual tcp_dlm_scaling leftover after the create/remove/rename
		 * EX-pin fix). */
		if (S_ISDIR(VFS_I(ip)->i_mode)) {
			static atomic_t p119stk = ATOMIC_INIT(0);
			if (atomic_inc_return(&p119stk) <= 3)
				mxfs_probe_stack();
		}
		/* Mark in-core stale for DLM cold-reload on next access. */
		xfs_iflags_set(ip, XFS_ISTALE_CAW);
		error = 0;
		goto flush_out;
	}

	/*
	 * (design review DLM-epoch LINEAGE guard) — closes the
	 * hole.  We hold EX here, but holding EX is NOT sufficient: a node
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
	    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
	    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    ip->i_mxfs_dirty_seq != ip->i_mxfs_ex_grant_seq &&
	    /* c7ee71c6 active demote == sanctioned (see P119 above) */
	    (ip->i_dlm_routed_iclus || ip->i_dlm_demoter == NULL) &&
	    !mxfs_cores_commit_flush) {
		static atomic_t epsk = ATOMIC_INIT(0);
		if (atomic_inc_return(&epsk) <= 4000)
			mxfs_probe("mxfs: P17B-EPOCH-GHOST-SKIP ino=%llu incore_mode=0%o disk_mode=0%o dirty_seq=%llu ex_grant_seq=%llu incore_nlink=%u disk_nlink=%u comm=%s\n",
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
	 * RESURRECTION GUARD (instrumented, PROVEN dir_reuse_coherency
	 * 2/tcp root): xfsaild flushes a stale-live in-core inode whose COHERENT
	 * on-disk copy a PEER already FREED (disk mode=0 nlink=0, di_gen bumped
	 * past ours).  ~201 such flushes per run (P-IRESURRECT, P119+P17B both 0x)
	 * RESURRECT the freed inode -> its data block, already freed+reallocated to
	 * the reused dir's LEAF, is double-claimed -> the dir leaf daddr holds .md5
	 * FILE data -> EFSBADCRC / lookup-fail.  The P119 (i_dlm_mode==EX)
	 * and P17B (dirty_seq==ex_grant_seq) guards MISS these: the peer
	 * freed our UNPUBLISHED inode without BASTing us, so i_dlm_mode is a STALE
	 * EX and dirty_seq==ex_grant_seq.  Reliable signal = the coherent on-disk
	 * inode (dip, the cluster buffer re-read at acquire/flush) is FREE and a
	 * SMALL-DELTA-LATER incarnation: di_mode==0 && di_nlink==0 &&
	 * 1 <= (u32)(disk_gen - incore_gen) <= MXFS_RESURRECT_GEN_WINDOW.  XFS
	 * increments i_generation by exactly 1 on each free (xfs_inode_util.c), so a
	 * resurrection lagging N peer-frees has disk_gen = incore_gen + N with N
	 * SMALL (the inode NUMBER is reused at most a few dozen times across the
	 * test's rm-rf rounds).  We must NOT use disk_gen > incore_gen (v1
	 * REGRESSION, readdir=0 EVERY round incl round 1) NOR == incore_gen+1 (v2,
	 * never matched the real dirwr=0 timing where N>1): a freshly chunk-
	 * allocated inode's disk slot carries a chunk-init RANDOM gen (get_random_u32)
	 * independent of our in-core gen, so `>` fires ~50% on LEGIT new-inode first
	 * flushes -> never persisted -> readdir=0 ("cross-node random gens
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
	    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
	    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    be16_to_cpu(dip->di_mode) == 0 && be32_to_cpu(dip->di_nlink) == 0 &&
	    VFS_I(ip)->i_mode != 0 &&
	    mxfs_rgw_delta >= 1 &&
	    mxfs_rgw_delta <= (u32)mxfs_resurrect_gen_window) {
		static atomic_t rsrk = ATOMIC_INIT(0);
		if (atomic_inc_return(&rsrk) <= 4000)
			mxfs_probe("mxfs: P25-RESURRECT-SKIP ino=%llu incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u incore_nlink=%u disk_nlink=%u i_dlm_mode=%u comm=%s\n",
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
	 * WRITE-BOUNDARY TORN-DINODE BARRIER (instrumented +
	 * design review design): the PROVEN deepest root of zero_silent_loss is that the
	 * dir inode's in-core if_nextents (the count copied into di_nextents by
	 * xfs_inode_to_disk below) DISAGREES with the actual number of extents in
	 * the in-core iext tree (di_nextents=14 vs 13-record leaf; 
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

			mxfs_probe_ratelimited(
				"mxfs: P74-IFNEXT-SKEW ino=%llu if_nextents=%llu real_iext=%llu fmt=%d comm=%s — reconciling to real count (torn-dinode barrier)\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_df.if_nextents,
				(unsigned long long)real,
				ip->i_df.if_format, current->comm);
			if (atomic_inc_return(&p74skew) == 1)
				mxfs_probe_stack();
			ip->i_df.if_nextents = real;
		}
	}

	/*
	 * FORMAT/LITERAL-AREA TORN-DINODE BARRIER
	 * (instrumented; PROVEN durable on-disk root).  xfs_inode_to_disk
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
	 * (durable torn dir-inode ino 0x1c001b2 on a barrier dir).
	 *
	 * We hold the ILOCK (fork frozen + authoritative) and — having passed
	 * the EX discriminator and P17B epoch-ghost guard above — this
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
				mxfs_probe("mxfs: P78-FMT-TORN-FIX ino=%llu newfmt=%d ondisk_fmt=%d nextents=%llu ili_fields=0x%x forcing=0x%x comm=%s\n",
					(unsigned long long)ip->i_ino,
					ip->i_df.if_format, dip->di_format,
					(unsigned long long)ip->i_df.if_nextents,
					iip->ili_fields, want, current->comm);
			iip->ili_fields |= want;
		}
	}

	/*
	 * WRITER-SIDE ORDERING FIX (zero_silent_loss): for a BTREE-format
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
	 * instrumented (a)-discriminator (design review 2nd consult):
	 * dir_reuse_coherency ends with the dir's LEAF index referencing more
	 * entries than the DATA fork holds (di_nextents reverted nx=2->1 while the
	 * leaf persisted).  Catch the durable extent-map REVERT in the act: a
	 * DIRECTORY iflush about to write a SMALLER in-core data-fork extent count
	 * over a LARGER on-disk one.  If this fires, design review root (a) (stale iflush
	 * reverting the parent dinode extent map) is CONFIRMED and the fix is to
	 * FENCE it (skip the shrinking flush unless authoritative).  Log-only,
	 * multinode dir, capped.  dip here is the cluster buffer being overwritten,
	 * so be32(dip->di_nextents) is the value we are about to clobber.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
	    (xfs_extnum_t)be32_to_cpu(dip->di_nextents) > ip->i_df.if_nextents) {
		static atomic_t p32nx = ATOMIC_INIT(0);
		if (atomic_inc_return(&p32nx) <= 2000)
			mxfs_probe("mxfs: P32-IFLUSH-NXSHRINK ino=%llu incore_nx=%llu disk_nx=%u incore_size=%lld disk_size=%lld relflush=%d dlm_mode=%u dirty_seq=%llu ex_gseq=%llu comm=%s — about to write SMALLER dir extent map over a larger on-disk one (extent-map revert)\n",
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
	 * P32F-NXSHRINK-FENCE (instrumented ENFORCEMENT of the P32 probe
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
		    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
		    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
		    (xfs_extnum_t)be32_to_cpu(dip->di_nextents) >
			ip->i_df.if_nextents) {
			uint32_t cur_ep = mxfs_v5_dlm_inode_dir_epoch(
				mp->m_mxfs_dlm, ip->i_ino);

			/* incarnation-qualified.  A raw `>` here fenced
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
	 * D3 ROOT FIX arm 2 — dead-incarnation flush
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
	/* +design review: WRITE-POISON — the marker alone forbids the flush (gen
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
	 * — DETERMINISTIC FENCED-FLUSH FAULT.  Definition, rationale
	 * and the knob contract live at the module_param in xfs_mxfs_dlm.c.
	 * Placed with the real fences and shaped IDENTICALLY to them (set
	 * ISTALE_CAW, set i_dlm_stale, error = 0, goto flush_out) so the state
	 * it produces is the state they produce: an abandoned publication with
	 * i_mxfs_pub_flush_seq UNSTAMPED and the obligation still open.
	 * Disarmed by default; costs one READ_ONCE of a zero on the fast path.
	 */
	{
		extern unsigned long long mxfs_iflush_fence_fault_ino;
		extern int mxfs_iflush_fence_fault_n;
		extern atomic_t mxfs_iflush_fence_fault_hits;

		if (unlikely(READ_ONCE(mxfs_iflush_fence_fault_ino) ==
			     (unsigned long long)ip->i_ino)) {
			int fh = atomic_inc_return(&mxfs_iflush_fence_fault_hits);
			int fn = READ_ONCE(mxfs_iflush_fence_fault_n);

			if (!fn || fh <= fn) {
				pr_warn("mxfs: P-IFLUSH-FENCE-FAULT ino=%llu hit=%d bound=%d pend=%llu dur=%llu flush=%llu dlm_mode=%u comm=%s — INJECTED fenced flush; obligation deliberately left open\n",
					(unsigned long long)ip->i_ino, fh, fn,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					(unsigned long long)ip->i_mxfs_pub_flush_seq,
					ip->i_dlm_mode, current->comm);
				xfs_iflags_set(ip, XFS_ISTALE_CAW);
				ip->i_dlm_stale = true;
				ip->i_dlm_stale_src = 99;
				error = 0;
				goto flush_out;
			}
		}
	}

	/*
	 * D3 ROOT FIX arm 3 — dir EPOCH flush fence
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
		    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
		    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation) {
			uint32_t cur_ep = mxfs_v5_dlm_inode_dir_epoch(
				mp->m_mxfs_dlm, ip->i_ino);

			/*
			 * ROOT FIX (instrumented, proven on test31 ino
			 * 4748168).  This site compared RAW.  That is exactly
			 * what introduced mxfs_dir_epoch_superseded
			 * to stop, and mxfs_dlm.h's declaration names THIS
			 * fence as one of the two consumers that "must go
			 * through" it — yet only the P32F arm above and the
			 * P194/P195 gate in libxfs/xfs_dir2.c were converted.
			 * The extern decl for the predicate was even copied
			 * into this block (above) and then never called.
			 *
			 * The raw compare fences a dir whose baseline was
			 * never established (valid_epoch = 0, the documented
			 * "no baseline" sentinel) against a master epoch that
			 * belongs to a PREVIOUS incarnation of the same inode
			 * NUMBER — the CAW dir_epoch is a property of the
			 * number, not of an incarnation (xfs_inode.h's
			 * i_dlm_dir_valid_incarn block, which names this fence
			 * and the silent-mkdir-loss it caused).
			 *
			 * Measured consequence beyond the known loss shape:
			 * the fence abandons the flush with error = 0 and
			 * WITHOUT stamping i_mxfs_pub_flush_seq, so the
			 * publication obligation (pending != durable) can
			 * never close.  The release drain then re-logs the
			 * "clean-but-unlanded" core (P146V) on every attempt,
			 * and xfs_trans_log_inode bumps pending_seq each time
			 * — the drain's own repair feeds the counter it is
			 * waiting on.  test31, 32/caw, 0.17.4: 120 P32E on
			 * ino 4748168, 1:1 with 120 P146V and 120 P176
			 * (cls=UNCOPIED pending=577..643 while flush stayed
			 * frozen at 4), then P-INODE-WEDGE tries=666
			 * causes=0x1 and a force-shutdown of the whole mount.
			 *
			 * The A/B lever is the existing mxfs.dir_epoch_incarn_gate
			 * (0 = pre-fix raw compare inside the predicate), which
			 * now covers this arm too instead of bypassing it.
			 */
			bool p32e_raw = cur_ep > ip->i_dlm_dir_valid_epoch;
			bool p32e_sup = mxfs_dir_epoch_superseded(ip, cur_ep);

			/*
			 * DIVERGENCE PROBE: every firing of this counts a
			 * flush the raw compare would have fenced and the
			 * contract predicate does not.  A non-zero count is
			 * the direct measurement that the omission mattered;
			 * zero means this inode class fell through to the
			 * same verdict and the wedge has another cause.
			 */
			if (p32e_raw && !p32e_sup) {
				static atomic_t p32ed = ATOMIC_INIT(0);

				if (atomic_inc_return(&p32ed) <= 400)
					pr_warn("mxfs: P32E-RAWDIVERGE ino=%llu valid_epoch=%u valid_incarn=%u incarn=%u cur_epoch=%u unpub=%d self_created=%d pend=%llu dur=%llu flush=%llu comm=%s — raw compare would have fenced this dir flush; incarnation-qualified predicate says NOT superseded\n",
						(unsigned long long)ip->i_ino,
						ip->i_dlm_dir_valid_epoch,
						ip->i_dlm_dir_valid_incarn,
						VFS_I(ip)->i_generation, cur_ep,
						ip->i_dlm_unpublished ? 1 : 0,
						ip->i_mxfs_self_created ? 1 : 0,
						(unsigned long long)ip->i_mxfs_pub_pending_seq,
						(unsigned long long)ip->i_mxfs_pub_durable_seq,
						(unsigned long long)ip->i_mxfs_pub_flush_seq,
						current->comm);
			}

			if (p32e_sup) {
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
	 * sess-tcp (design review fence design, `docs/history/sess-tcp-fix-design-fence-stale-dir-inode-fork-flush.md`):
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
			mxfs_probe("mxfs: P-DIRIFLUSH ino=%llu dlm_mode=%u incore_blk0_fsb=%llu incore_nx=%llu disk_nx=%u dir_gen=%llu loaded_gen=%u relflush=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode,
				(unsigned long long)b0,
				(unsigned long long)ip->i_df.if_nextents,
				(dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC)) ?
					be32_to_cpu(dip->di_nextents) : 0xffffffff,
				(unsigned long long)ip->i_dlm_dir_gen,
				ip->i_dlm_dir_loaded_gen,
				xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) ? 1 : 0,
				current->comm);
	}

	/*
	 * (instrumented ENFORCEMENT — the "next step" the prior P-DIRIFLUSH
	 * probe deferred): a node that does NOT hold the dir's DLM in EX must not
	 * publish the dir inode's data fork.  P-DIRIFLUSH PROVED ino=131 is flushed
	 * with dlm_mode=0 (NL) by nodes that have released EX; that stray xfsaild
	 * flush writes a STALE in-core extent map over the current EX owner's
	 * authoritative map (the extent-map flip-flop), orphaning a logical
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
	 * (design review "first-published wins" iflush FENCE): the
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
	    dip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC) &&
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
	 * < > DATA-REGION GAP FENCE (instrumented, PROVEN DISK-TORN root):
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
		if (ghole && !ip->i_mxfs_dir_hole_known) {
			/* < > DETECTOR-ONLY (enforcement reverted): the
			 * gap is the PROVEN DISK-TORN root (a divergent cross-node grow
			 * left this node's in-core dir map with a hole between data
			 * blocks).  Skipping the flush here merely defers the tear: the
			 * gapped in-core fork then survives into xfs_dir2_leaf_addname
			 * which writes a leaf entry against the hole -> kernel OOPS
			 * (worse than the controlled DABUF_MAP_HOLE shutdown).  The real
			 * fix is upstream — prevent the divergent grow / heal the gapped
			 * fork BEFORE addname uses it.  Detect + log only for now.
			 *
			 * 0.75.63: a hole is also the ordinary result of
			 * xfs_dir2_shrink_inode freeing an emptied middle data block
			 * (the node-format removename path does this for every such
			 * block) or of adopting a holey canonical disk image; those
			 * set i_mxfs_dir_hole_known and are not reported.  Only a hole
			 * with no known origin carries the divergent-grow signature. */
			mxfs_probe_ratelimited(
				"mxfs: P-IFLUSH-GAP-DETECT ino=%llu nextents=%llu disize=%lld gen=%u dlm_mode=%u comm=%s — in-core dir data fork has a HOLE between data blocks with no known origin (no local middle-block shrink, no holey disk adopt): possible divergent-grow torn map (DABUF_MAP_HOLE / leaf-addname-oops source)\n",
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
			mxfs_probe("mxfs: PW-IFLUSH ino=%llu fmt=%d nx=%llu size=%lld nlink=%u pin=%d in_ail=%d fields=0x%x last=0x%x lsn=0x%llx daddr=%lld comm=%s realns=%llu\n",
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
	 * D-CONCURRENT-CREATE-RACE-PEER-AG-ZERO-EXTENT-RECORDS-FILES-EMPTY-0920
	 * (2-node TCP rig, concurrent-create-race laps s525g and s527f: 137 and
	 * 89 of 200 files read empty on test2 with 'Metadata corruption detected
	 * at xfs_bmap_validate_extent_raw' and a zero bmap record under
	 * di_nextents=1).  On a multi-node mount the cluster buffer is not
	 * always this inode's last durable image: a reload that keeps the cached
	 * buffer protected adopts the peer's dinode from a private platter read
	 * and leaves the buffer slot untouched, and xfs_iflush_fork above copies
	 * fork bytes only when the fork itself was logged, so a core-only flush
	 * published the new di_nextents / di_size over the slot's stale fork
	 * bytes.  Measured at this point on s527f: ten flushes by xfsaild with
	 * ili_fields=CORE|TIMESTAMP, one in-core extent and sixteen zero bytes
	 * staged.  The in-core forks are published whenever the staged bytes
	 * differ, so the slot's history no longer matters.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		mxfs_iflush_fork_publish(ip, dip, iip, bp);

	/*
	 * 0.84.18 (D-0963): dip now holds exactly the shortform directory
	 * image the cluster buffer will write.  Record it as this node's own
	 * publication so the stale-gen refresh that later reads it back from
	 * the platter recognises it and does not merge it as a peer's image
	 * (which re-added every entry removed since this flush).  Only under
	 * our own EX: a directory fork is published by its EX holder alone.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    dip->di_format == XFS_DINODE_FMT_LOCAL &&
	    ip->i_dlm_mode == MXFS_LOCK_EX && dip->di_size) {
		extern void mxfs_dir_sf_own_record(struct xfs_inode *,
						   const void *, uint32_t);

		mxfs_dir_sf_own_record(ip, XFS_DFORK_DPTR(dip),
				       (uint32_t)be64_to_cpu(dip->di_size));
	}

	/*
	 * v0.3.120: P64-INSTR — capture iflush'd content for SF dirs.
	 * Compare with P55-INSTR (post-bast_process disk read) to verify
	 * iflush serializes the expected (post-modification) ip state.
	 *
	 * Hypothesis 2 from state.md: iflush might serialize stale
	 * pre-modification state, explaining Mode A.  P64 captures what
	 * iflush actually writes to the buf for cross-correlation.
	 */
	/* P8-SFIFLUSH — platter ledger (gated dir_relverify):
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
		mxfs_probe("mxfs: P8-SFIFLUSH ino=%llu size=%lld daddr=%lld in_ail=%d names=[%s] comm=%s realns=%llu\n",
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
	 * (run14d) PRODUCER PROBE — cross_write_read torn dir dinode.
	 * A directory flushed in EXTENTS format whose FIRST data-fork extent
	 * record does not decode to a valid filesystem block was copied from an
	 * in-core fork that is mid-LOCAL->EXTENTS-conversion torn (di_format
	 * EXTENTS in the core but the literal still holds stale shortform dir
	 * bytes, e.g. "data_node…").  Such a dinode PASSES the structural write
	 * verifier (xfs_dinode_verify decodes di_nextents vs forkoff only) but
	 * FAILS every reader's xfs_iformat_extents -> EUCLEAN -> FS shutdown
	 * (PROVEN ino=444 .mxfs_test/cross_write_read, 16-node).  Catch
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

				mxfs_probe("mxfs: P-IFLUSH-DIRTORN ino=%llu nx=%llu forkoff=%u startblk=0x%llx cnt=0x%llx first16=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x comm=%s pid=%d realns=%llu — torn LOCAL->EXTENTS dir dinode about to be written; stack:\n",
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
				mxfs_probe_stack();
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
	 * success path only — this image is now in the cluster buffer
	 * and carries every committed change up to pub_seq_at_copyin.  The
	 * obligation is NOT discharged yet (the buffer has not been written);
	 * xfs_iflush_finish does that from the write completion.
	 */
	ip->i_mxfs_pub_flush_seq = pub_seq_at_copyin;
	/* this copy-in carries the unlink conversion (the arm runs
	 * under ILOCK EXCL, this copy-in under ILOCK SHARED, so a pre-arm
	 * in-flight flush can never reach here with the flag set). */
	/* (D-0351): for a FREE obligation only the FREE image
	 * (mode 0, committed) discharges — a pending free never marks.
	 * (D-0524): which image this write carries is decided on the
	 * store entry under its lock and published as the entry's in-flight
	 * token (mxfs_pubob_stage_flush); the flag is only the completion's
	 * cheap hint that a token may exist. */
	if (xfs_iflags_test(ip, MXFS_IF_PUBOB) &&
	    mxfs_pubob_stage_flush(ip->i_mount, ip))
		xfs_iflags_set(ip, MXFS_IF_PUBOB_FLUSHED);
	/* P241: a fresh copy-in supersedes any prior overlay of this
	 * inode's slot — the staged image is current again, so a later
	 * discharge is honest.  Disarm the blind-discharge tripwire. */
	xfs_iflags_clear(ip, MXFS_IF_CLMERGE_HIT);
	/*
	 * (s439 board, 84 of 2088 FREE claims): MXFS_IF_PUB_SKIPPED
	 * is a verdict about the image staged in a PREVIOUS submit (P235
	 * masked a landed, re-logged slot and set it unconditionally); that
	 * round's completion skipped the item at the ili_last_fields check
	 * (nothing was flushed that round) and never cleared it, so THIS
	 * copy-in's completion found the stale flag, re-armed instead of
	 * advancing durable, and the obligation was later closed from the
	 * buffer image.  Every skip verdict is taken at submit, after the
	 * copy-in, so a fresh copy-in may — and must — start with a clean
	 * flag: only a skip of THESE bytes may re-arm their completion.
	 */
	xfs_iflags_clear(ip, MXFS_IF_PUB_SKIPPED);
	/* P240 (design review 2c chain-of-custody): pair every sanctioned-
	 * release copy-in with its BUFFER IDENTITY, so a later overlay trace
	 * (P239) proves whether the condemning merge ran on the SAME buffer
	 * instance (theory i: flag sub-window) or a DIFFERENT one (theory ii:
	 * instance replacement — the run64 blindness family).  RELFLUSH-gated:
	 * a few lines per dirty-at-release file, nothing on hot paths. */
	if (unlikely(xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH)))
		mxfs_probe_ratelimited(
		    "mxfs: P240-COPYIN-ID ino=%llu bp=%px flush=%llu pend=%llu dur=%llu comm=%s realns=%llu\n",
			(unsigned long long)ip->i_ino, bp,
			(unsigned long long)ip->i_mxfs_pub_flush_seq,
			(unsigned long long)ip->i_mxfs_pub_pending_seq,
			(unsigned long long)ip->i_mxfs_pub_durable_seq,
			current->comm,
			(unsigned long long)ktime_get_real_ns());
	/*
	 *  — record WHICH TENURE these bytes were staged
	 * under.  The buffer is submitted later (xfsaild), and the grant can be
	 * lost in between; the cluster-write site compares this against the live
	 * i_dlm_epoch to see whether it is publishing a dead tenure's image.
	 * Success path only: a skipped flush staged nothing.
	 *
	 * the release path stores mode=NL and epoch++ as two plain
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
	/*
	 * (D-0351): mint the FREE-publication claim for the image just
	 * staged under the P55C sanction.  The cluster merge keeps this slot
	 * (instead of restoring the platter's live predecessor over it) and the
	 * partial-write mask publishes it at inode-NL only while the claim
	 * validates against THIS buffer, THIS flush_seq, the open obligation
	 * and the SAME AG tenure — see mxfs_freepub_claim_valid.
	 */
	if (p55c_claim_epoch) {
		static atomic_t p_fpc = ATOMIC_INIT(0);

		WRITE_ONCE(ip->i_mxfs_freepub_gen, be32_to_cpu(dip->di_gen));
		WRITE_ONCE(ip->i_mxfs_freepub_seq, ip->i_mxfs_pub_flush_seq);
		WRITE_ONCE(ip->i_mxfs_freepub_bp, bp);
		smp_wmb();
		WRITE_ONCE(ip->i_mxfs_freepub_epoch, p55c_claim_epoch);
		if (atomic_inc_return(&p_fpc) <= 2000)
			mxfs_probe("mxfs: P-FREEPUB-CLAIM ino=%llu gen=%u epoch=%llu seq=%llu bp=%px daddr=%lld img_mode=0%o comm=%s — free image staged under a FREE-publication claim\n",
				(unsigned long long)ip->i_ino,
				be32_to_cpu(dip->di_gen),
				(unsigned long long)p55c_claim_epoch,
				(unsigned long long)ip->i_mxfs_pub_flush_seq, bp,
				(long long)xfs_buf_daddr(bp),
				be16_to_cpu(dip->di_mode), current->comm);
	}
flush_out:
	/* (D-0351): the copy-in (if any) has attached the item to the
	 * locked buffer — the release drain can see it; drop the gate. */
	if (p55c_pag) {
		mxfs_ag_pubwrite_end(p55c_pag);
		xfs_perag_put(p55c_pag);
		p55c_pag = NULL;
	}
	/*
	 * (D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380) — THE
	 * SINGLE CHOKEPOINT FOR "THIS FLUSH WAS ABANDONED".
	 *
	 * Eleven fences above return SUCCESS (error = 0) without reaching the
	 * i_mxfs_pub_flush_seq stamp, each on the premise that the platter is
	 * authoritative and the inode will be reloaded later.  That premise is
	 * sound; the bookkeeping was not.  The publication obligation
	 * (pending_seq != durable_seq) was left open with nothing on the
	 * RELEASE side able to resolve it, so the drain re-logged forever and
	 * the defer episode force-shut-down the whole mount.
	 *
	 * Detect it HERE rather than at each fence: "we are returning success,
	 * we did not stamp flush_seq, and an obligation is still open" is
	 * exactly the abandoned-publication condition, it is checked in ONE
	 * place, and it automatically covers any fence added later — including
	 * ones that do not bother to set i_dlm_stale.
	 *
	 * Triggering the release-side reload on i_dlm_stale instead was too
	 * broad: measured 199 firings across one 32-node board, all with
	 * stale_src=5 (a non-fence setter) and closed=0, i.e. a disk read and
	 * an adopt attempt each time for inodes no fence had abandoned.
	 */
	if (!error && ip->i_mxfs_pub_flush_seq != pub_seq_at_copyin &&
	    ip->i_mxfs_pub_pending_seq != ip->i_mxfs_pub_durable_seq) {
		WRITE_ONCE(ip->i_mxfs_pub_fenced, 1);
		/*
		 * ruling-2 Q2 MEASUREMENT (telemetry only — nothing
		 * acts on this verdict yet).  At the exact moment a fence
		 * abandons a publication, is the home image ALREADY canonically
		 * equal to what we owe?  If it usually is, the obligation is a
		 * bookkeeping artifact and can be closed by equivalence with a
		 * real proof behind it; if it usually is not, we genuinely owe
		 * a publication and the answer is the authority-reacquisition
		 * path, not an equality close.  `why` names the FIRST field
		 * that differs, so a run says which comparison is load-bearing
		 * rather than just "not equal".
		 */
		if (mxfs_home_equals_owed_probe) {
			const char *why = "?";
			bool eq = mxfs_home_equals_owed(ip, dip, &why);
			static atomic_t hoq = ATOMIC_INIT(0);

			if (atomic_inc_return(&hoq) <= 400)
				pr_warn("mxfs: P383-HOME-VS-OWED ino=%llu equal=%d why=%s pend=%llu dur=%llu flush=%llu cc_home=%llu iver=%llu mode=0%o dmode=%u gen_incore=%u gen_home=%u hmode=0%o hnlink=%u unpub=%d selfcr=%d deadgen=%u stale_src=%u relst=%u comm=%s — canonical comparison at a fence-abandoned publication\n",
					(unsigned long long)ip->i_ino, eq ? 1 : 0,
					why,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					(unsigned long long)ip->i_mxfs_pub_flush_seq,
					(unsigned long long)be64_to_cpu(dip->di_changecount),
					(unsigned long long)inode_peek_iversion(VFS_I(ip)),
					VFS_I(ip)->i_mode, ip->i_dlm_mode,
					/*
					 * gen is get_random_u32, so the
					 * two gens do NOT order — they only say
					 * "different incarnation".  The fields
					 * that actually discriminate WHICH side
					 * is stale are the next four: an
					 * unpublished / self-created incarnation
					 * means OUR image is the live one and we
					 * genuinely owe a publication; a
					 * dead-incarnation verdict means ours is
					 * the corpse and the obligation is void.
					 */
					VFS_I(ip)->i_generation,
					be32_to_cpu(dip->di_gen),
					be16_to_cpu(dip->di_mode),
					be32_to_cpu(dip->di_nlink),
					ip->i_dlm_unpublished ? 1 : 0,
					ip->i_mxfs_self_created ? 1 : 0,
					ip->i_mxfs_dead_incarn_gen,
					ip->i_dlm_stale_src,
					READ_ONCE(ip->i_mxfs_rel_state),
					current->comm);
		}
	}

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
 * cross-inode CLUSTER-BUFFER false-sharing fix (PROVEN root cause).
 *
 * A directory inode and an adjacent regular-file inode can live in the SAME
 * inode-cluster buffer (up to 64 inodes/cluster).  MXFS grants DLM locks
 * per-INODE but the buffer cache is per-CLUSTER.  When peers modify the DIR
 * inode under its EX DLM (made platter-durable before EX->NL via the
 * drain-before-unlock barrier + dir-data durability barrier), THIS
 * node's cached copy of the cluster buffer is never refreshed for the dir
 * slot: we hold NL on the dir, and the per-inode BAST only forces a re-read on
 * the next READ -- but a dirty co-resident CHILD pins the buffer resident and
 * the next access is a WRITE.  When xfsaild flushes the dirty child via
 * xfs_iflush_cluster, it writes the WHOLE cluster, carrying this node's STALE
 * dir slot back to disk and REVERTING the peers' committed dir entries
 * (PROVEN P-DIRFLUSH ino=4194434 count=4 written by test4, then count=2
 * written by test2 ~248ms later -> node1.txt/node4.txt LOST on disk).
 *
 * FIX: before the cluster buffer is submitted, FUA-read the CURRENT on-disk
 * cluster and OVERLAY the on-disk image of every FOREIGN directory inode (a
 * S_ISDIR dinode we are NOT flushing this round) so the durable peer-committed
 * dir is written back instead of our stale cached copy.
 *
 * Scope = directories only.  Dir writes are durable-before-visible here, so the
 * FUA read returns the committed dir, not a stale-in-cache value.  Regular-file
 * di_size does NOT have that guarantee (attempt-2 read a not-yet-durable
 * di_size=0 and re-wrote 0), so regular files are deliberately NOT merged.
 *
 * Safety (per design review architectural review):
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
 * D-CRASH-COLDREAD-STALE-SPLIT FIX-1 — LEDGER HONESTY AT
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
	/* P239 (design review 2c): UNCONDITIONAL identity trace for every
	 * overlay of a slot carrying an in-flight copy-in claim — pairs with
	 * P240 (copy-in side) by ino + bp pointer to settle theory (i)
	 * flag-sub-window vs theory (ii) buffer-instance replacement.  The
	 * behavioral rollback below stays RELFLUSH-gated.
	 *
	 * CLASSIFIER (consult #3): pcc (the PLATTER slot's
	 * changecount from the merge's own coherent read) vs icc (in-core
	 * iversion) decides whether this condemnation protects a PEER's
	 * newer image (pcc ahead of our landed knowledge = true staleness;
	 * fatal-tripwire class per design review once proven the only class) or
	 * reverts OUR OWN newer state while no peer ever wrote (icc > pcc
	 * with the wire grant never having left = provenance FALSE
	 * POSITIVE from in-core epoch churn — the mask predicate, not the
	 * data, is stale; making the tripwire fatal on this class would
	 * shut down healthy nodes).  Classify before enforcing (instrumented). */
	if (READ_ONCE(oip->i_mxfs_pub_flush_seq) !=
	    READ_ONCE(oip->i_mxfs_pub_durable_seq)) {
		/* CLASS DISCRIMINATORS (instrumented, classifier round 2):
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
		mxfs_probe_ratelimited(
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
	 * REFINEMENT (instrumented — the unconditional first cut was a
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
	 * FIX-C (design review P1, paired with FIX-B3): ALSO roll back for a
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
		/*
		 * (D-0351): the overlay replaced a slot that carried a
		 * FREE-publication claim on THIS buffer (a claim that still
		 * validated was kept by the mask and never reaches here, so
		 * this is the stale-claim class).  FAIL CLOSED: the write that
		 * follows carries the platter's live image, not the free image,
		 * so its completion must not discharge the FREE obligation —
		 * roll the watermark back, re-arm, drop the FLUSHED mark and
		 * retire the claim; the obligation stays open and the AG
		 * release gate keeps the AG held until a fresh copy-in lands.
		 */
		bool mrb_fp = READ_ONCE(oip->i_mxfs_freepub_epoch) &&
			READ_ONCE(oip->i_mxfs_freepub_bp) == (void *)mrb_bp;

		if (mrb_fp) {
			xfs_iflags_clear(oip, MXFS_IF_PUBOB_FLUSHED);
			mxfs_pubob_flush_abort(oip->i_mount, oip);	/* */
			mxfs_freepub_claim_clear(oip, "merge-overlaid");
		}
		if (!mrb_rel && !mrb_own && !mrb_fp)
			return;
		mrb_f = READ_ONCE(oip->i_mxfs_pub_flush_seq);
		mrb_d = READ_ONCE(oip->i_mxfs_pub_durable_seq);
		if (mrb_f == mrb_d)
			return;
		oip->i_mxfs_pub_flush_seq = mrb_d;
		xfs_iflags_set(oip, MXFS_IF_PUB_SKIPPED);
		mxfs_probe_ratelimited(
		    "mxfs: P238-CLMERGE-LEDGER-ROLLBACK ino=%llu slot=%d arm=%s cls=%s flush=%llu->%llu pend=%llu — overlay replaced a staged image; rolled the flush watermark back so the completion cannot discharge merged-away bytes\n",
			(unsigned long long)oip->i_ino, slot, arm,
			mrb_fp ? "freepub-stale" :
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
	uint64_t		authorit = 0;	/* c7ee71c6 same-tenure provenance — exempt from DEADINCARN overlay */
	uint64_t		curstage = 0;	/* FIX-B3: live staged image produced under the CURRENT tenure */
	/* D-CRASH-COLDREAD-STALE-SPLIT FIX-1: attached
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
	 * (design review design-consult, PROVEN ROOT): this merge does a SYNCHRONOUS
	 * forced SCSI FUA read (mxfs_pal_scsi_read_fua_bdev) while xfsaild holds
	 * the inode-CLUSTER buffer lock (b_lock_ip = xfs_inode_item_push trylock).
	 * On the SCST target a forced-FUA read can stall/error (scsi_eh active) —
	 * that is the cache_coherency release-path DRAIN WEDGE: ino=128's cluster
	 * buffer left locked + IFLUSHING + in_ail with no live holder, peer EX
	 * times out -> shutdown.  When fua_disable=1 (the module DEFAULT since
	 * ), reads already route through the coherent shared cache, so this
	 * FUA-overlay is BOTH unnecessary AND the thing that wedges the flush.
	 * Skip it entirely under fua_disable.
	 *
	 * REVISED: skipping the merge under fua_disable left the
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
		/* FIX-1: record every attached inode by slot (before any
		 * of the protection-mask decisions below skip it) — the overlay
		 * ledger-rollback needs the inode even for slots the mask does
		 * NOT protect; a mask miss is precisely the hazard. */
		slot = ip->i_imap.im_boffset >> inodelog;
		if (slot >= 0 && slot < ni && slot < 64)
			slot_ip[slot] = ip;
		/*
		 * FIX-B3 (c7ee71c6, design review priority-1 design): the mask
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
		 * an attached inode whose flush AUTHORITY is revoked
		 * (the P119 non-EX skip / epoch skip above refused its
		 * copy-in) leaves only a prior-tenure image in the buffer; the
		 * durable disk slot is the authority.  Leave its flushing bit
		 * clear so the overlay below restores it (PROVEN clobber:
		 * P133-DIRINO-REVERT on ino=131, p134b storm).  An EX-held
		 * same-tenure inode that merely could not flush this round
		 * (pinned/trylock-fail) keeps its bit — its buffer image is
		 * this node's own authoritative prior flush.
		 */
		/*
		 * — mirror of the xfs_iflush P55 co-resident
		 * committed-change exception.  An attached DIR we hold at PR with a
		 * pending committed change (in_ail) has an AUTHORITATIVE buffer image:
		 * xfs_iflush (P55) copied our committed dirent REMOVAL into the buffer
		 * this round.  PR<->EX exclusivity guarantees no peer wrote (or freed/
		 * realloc'd) the on-disk slot since we took PR, so disk is STALE and the
		 * buffer wins; PR-hold => same incarnation (no ghost risk).  KEEP the
		 * flushing bit so the overlay below does NOT copy the stale disk image
		 * back over our removal (PROVEN without this the merge overlaid
		 * disk AFTER P55's flush and RESURRECTED node2's renamed-away n2_rNN ->
		 * tcp_dlm_scaling "drained got=N").  Precedes the revoke. */
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
		/*
		 * (D-0351, design-consult ruling): a staged FREE image carries an
		 * explicit publication CLAIM (minted by the P55C copy-in under
		 * the AG tenure).  At inode-NL with no RELFLUSH token it passes
		 * none of the predicates below, so the restore arm put
		 * the platter's LIVE predecessor back over it and the free never
		 * landed (s437: 56/123 P-DIALLOC-DISKLIVE).  A VALID claim makes
		 * the slot authoritative: the platter can only hold our own
		 * predecessor (the AG release gate holds the AG while the
		 * obligation is open, so no peer published since).  A claim on
		 * THIS buffer that no longer validates falls through to the
		 * restore arms, whose ledger rollback fails it closed (the
		 * obligation stays open, the AG stays held).
		 */
		if (READ_ONCE(ip->i_mxfs_freepub_epoch) &&
		    slot >= 0 && slot < ni) {
			const char *fp_why = NULL;
			struct xfs_dinode *fp_img =
				xfs_buf_offset(bp, slot << inodelog);

			if (mxfs_freepub_claim_valid(ip, bp, bp->b_pag, fp_img,
						     &fp_why)) {
				static atomic_t p_fpk = ATOMIC_INIT(0);

				flushing |= (1ULL << slot);
				authorit |= (1ULL << slot);
				if (atomic_inc_return(&p_fpk) <= 2000)
					mxfs_probe("mxfs: P-FREEPUB-KEEP ino=%llu slot=%d gen=%u epoch=%llu bp=%px comm=%s — merge keeps the claimed free image (no platter restore)\n",
						(unsigned long long)ip->i_ino, slot,
						ip->i_mxfs_freepub_gen,
						(unsigned long long)ip->i_mxfs_freepub_epoch,
						bp, current->comm);
				continue;
			}
			if (READ_ONCE(ip->i_mxfs_freepub_bp) == (void *)bp)
				pr_warn_ratelimited(
				    "mxfs: P-FREEPUB-CLAIM-STALE site=merge ino=%llu slot=%d why=%s gen=%u claim_epoch=%llu ag_epoch=%llu rel_epoch=%llu demoting=%d flush=%llu seq=%llu img_mode=0%o img_gen=%u comm=%s — claim on this buffer no longer validates; restore proceeds fail-closed\n",
					(unsigned long long)ip->i_ino, slot, fp_why,
					ip->i_mxfs_freepub_gen,
					(unsigned long long)ip->i_mxfs_freepub_epoch,
					(unsigned long long)(bp->b_pag ?
						READ_ONCE(bp->b_pag->pag_mxfs_grant_epoch) : 0),
					(unsigned long long)(bp->b_pag ?
						READ_ONCE(bp->b_pag->pag_mxfs_rel_epoch) : 0),
					bp->b_pag ? (int)READ_ONCE(bp->b_pag->pag_dlm_demoting) : -1,
					(unsigned long long)ip->i_mxfs_pub_flush_seq,
					(unsigned long long)ip->i_mxfs_freepub_seq,
					be16_to_cpu(fp_img->di_mode),
					be32_to_cpu(fp_img->di_gen), current->comm);
		}
		if (!xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
		    (ip->i_dlm_mode != MXFS_LOCK_EX ||
		     ip->i_mxfs_dirty_seq != ip->i_mxfs_ex_grant_seq))
			continue;
		slot = ip->i_imap.im_boffset >> inodelog;
		if (slot >= 0 && slot < ni) {
			flushing |= (1ULL << slot);
			/*
			 *  (instrumented, PROVEN via
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
	 * revert? this is no longer dir-only.  A regular-file inode
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
		if (be16_to_cpu(dip->di_magic) != MXFS_DINODE_MAGIC)
			continue;
		if (be16_to_cpu(dip->di_mode) != 0) {
			foreign_dir = true;
			break;
		}
	}
	if (!foreign_dir)
		return;

	/*
	 * a dirty buf-log-item means a buf-logged range
	 * is pending + not durable.  The ONLY field buf-logged on an inode-CLUSTER
	 * buffer is di_next_unlinked (updated in-place under the AGI lock during
	 * iunlink; inode CORE changes go through the inode log item, NOT the buf
	 * log).  The old code SKIPPED the whole overlay here — but that left the
	 * cross-node stale co-resident-slot CLOBBER window OPEN precisely during the
	 * inactivation/iunlink churn that wedges the 2/tcp suite (PROVEN a
	 * peer's dir/inode slot overwritten with this node's stale image -> later
	 * xfs_iget verify-fail on the cluster -> shutdown; repro = dlm_fairness +
	 * rsync_paired + crash_consistency on one prep).  Do NOT skip.
	 *
	 * the companion rule — "PRESERVE each overlaid slot's
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
			 * `docs/history/sess-tcp-seed-root-ino131-free-lost-to-evict-ring-overflow.md`).
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
			 * is never reverted (that case keeps the /rules).
			 */
			if (!(be16_to_cpu(ddisk->di_magic) == MXFS_DINODE_MAGIC &&
			      be16_to_cpu(dbuf->di_magic) == MXFS_DINODE_MAGIC &&
			      S_ISDIR(be16_to_cpu(ddisk->di_mode)) &&
			      S_ISDIR(be16_to_cpu(dbuf->di_mode)) &&
			      be32_to_cpu(dbuf->di_gen) != be32_to_cpu(ddisk->di_gen)))
				continue;
			/*
			 *  (PROVEN BY INSTRUMENT — see the
			 * authorit mask above): a same-tenure sanctioned flush
			 * of a NEW incarnation legitimately has buf_gen !=
			 * disk_gen while the deferred-destage platter lags.
			 * The "never AHEAD of disk" premise of this arm died
			 * with eager=0.  Never overlay an authoritative slot.
			 */
			if (authorit & (1ULL << i)) {
				mxfs_pal_log(MXFS_LOG_DEBUG,
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
		 * FIX-B3 (design review P1): a slot whose LIVE staged image was
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
		    be16_to_cpu(dbuf->di_magic) == MXFS_DINODE_MAGIC &&
		    be16_to_cpu(ddisk->di_magic) == MXFS_DINODE_MAGIC &&
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
		 * the durable on-disk image of a FOREIGN slot (one we
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
		if (be16_to_cpu(ddisk->di_magic) != MXFS_DINODE_MAGIC)
			continue;

		bmode = (be16_to_cpu(dbuf->di_magic) == MXFS_DINODE_MAGIC)
			? be16_to_cpu(dbuf->di_mode) : 0;
		dmode = be16_to_cpu(ddisk->di_mode);
		buf_alloc  = (bmode != 0);
		disk_alloc = (dmode != 0);

		/*
		 * NEVER zero an allocated buffer slot to free: disk-free while
		 * buffer-allocated is the inode-reuse / eviction direction,
		 * handled elsewhere and never safe to force here.
		 */
		if (!disk_alloc && buf_alloc)
			continue;

		if (memcmp(dbuf, ddisk, inodesize) == 0)
			continue;

		/*
		 * FIX (PROVEN cross_visibility shortform self-revert): for
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
		 * overlaying disk is correct and still happens.
		 */
		if (be16_to_cpu(dbuf->di_magic) == MXFS_DINODE_MAGIC &&
		    S_ISDIR(bmode) &&
		    XFS_DFORK_FORMAT(dbuf, XFS_DATA_FORK) == XFS_DINODE_FMT_LOCAL &&
		    XFS_DFORK_FORMAT(ddisk, XFS_DATA_FORK) == XFS_DINODE_FMT_LOCAL) {
			struct xfs_dir2_sf_hdr *bsf =
				(struct xfs_dir2_sf_hdr *)XFS_DFORK_DPTR(dbuf);
			struct xfs_dir2_sf_hdr *dsf =
				(struct xfs_dir2_sf_hdr *)XFS_DFORK_DPTR(ddisk);

			if (bsf->count > dsf->count) {
				mxfs_pal_log(MXFS_LOG_DEBUG,
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
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "mxfs: P-CLMERGE restored ino=%llu slot=%d bmode=0%o dmode=0%o realns=%llu",
			    (unsigned long long)XFS_AGINO_TO_INO(mp, agno,
				first_agino + i),
			    i, bmode, dmode,
			    (unsigned long long)ktime_get_real_ns());
	}

	/*
	 * install site 5 — PROVEN in-core fossil reverter (instrumented):
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
				mxfs_probe_ratelimited("mxfs: P129-CLSKIP ino=%llu why=RECLAIM_OR_FLUSHING iflags=0x%lx\n",
					(unsigned long long)ip->i_ino, ip->i_flags);
			continue;
		}
		/* test knob dbg_ail_pin_ino: a sibling's push must not flush the
		 * pinned inode through the cluster either (see xfs_inode_item.c) */
		if (mxfs_dbg_ail_pinned(ip))
			continue;
		if (xfs_ipincount(ip)) {
			if (atomic_read(&mxfs_ailstuck_probe))
				mxfs_probe_ratelimited("mxfs: P129-CLSKIP ino=%llu why=PINNED ipin=%d\n",
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
				mxfs_probe_ratelimited("mxfs: P129-CLSKIP ino=%llu why=RECLAIM_OR_FLUSHING2 iflags=0x%lx\n",
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

				mxfs_probe_ratelimited("mxfs: P129-CLSKIP ino=%llu why=ILOCK_NOWAIT_FAIL count=%ld owner=%px ocomm=%s opid=%d\n",
					(unsigned long long)ip->i_ino,
					atomic_long_read(&ip->i_lock.count),
					otsk,
					otsk ? otsk->comm : "-",
					otsk ? task_pid_nr(otsk) : -1);
				if (otsk && mxfs_probe_on() &&
				    atomic_inc_return(&mxfs_ailstuck_odumps) <= 3)
					sched_show_task(otsk);
			}
			continue;
		}
		__xfs_iflags_set(ip, XFS_IFLUSHING);
		spin_unlock(&ip->i_flags_lock);

		/*
		 * LEAKER-CAPTURE (safe, no lock manipulation): the
		 * cache_coherency drain wedge is the root-dir inode (sb_rootino,
		 * ino=128) left IFLUSHING with its cluster buffer locked+DONE but
		 * never written.  IFLUSHING is set HERE; record which caller of
		 * xfs_iflush_cluster set it so the next repro names the path that
		 * abandons the flush (the one whose bwrite/relse never runs).
		 * Rate-limited, root-dir only -> negligible noise.
		 */
		if (ip->i_ino == mp->m_sb.sb_rootino)
			mxfs_probe_ratelimited(
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
			 * DEADLOCK FIX — release the
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
			/* deadlock fix — raw un-take (see above). */
			atomic_dec(&ip->i_mxfs_ilk_rd_held);
			up_read(&ip->i_lock);
			if (atomic_read(&mxfs_ailstuck_probe))
				mxfs_probe_ratelimited("mxfs: P129-CLSKIP ino=%llu why=PINNED2 ipin=%d\n",
					(unsigned long long)ip->i_ino, xfs_ipincount(ip));
			continue;
		}

		if (!xfs_inode_clean(ip)) {
			error = xfs_iflush(ip, bp);
			/*
			 * -EAGAIN = transient torn
			 * shortform dir fork (mid down-conversion) — skip this
			 * inode THIS round, leaving its ILI dirty in the AIL so
			 * the flush retries after the conversion settles.  Not
			 * an error: must not shut down or fail the buffer.
			 */
			if (error == -EAGAIN) {
				xfs_iflags_clear(ip, XFS_IFLUSHING);
				/* raw un-take (see deadlock fix above) */
				atomic_dec(&ip->i_mxfs_ilk_rd_held);
				up_read(&ip->i_lock);
				error = 0;
				continue;
			}
			if (atomic_read(&mxfs_ailstuck_probe))
				mxfs_probe_ratelimited("mxfs: P129-CLSKIP ino=%llu why=IFLUSH_RAN err=%d ili_fields=0x%x\n",
					(unsigned long long)ip->i_ino, error,
					iip->ili_fields);
		} else {
			xfs_iflags_clear(ip, XFS_IFLUSHING);
			if (atomic_read(&mxfs_ailstuck_probe))
				mxfs_probe_ratelimited("mxfs: P129-CLSKIP ino=%llu why=CLEAN ili_fields=0x%x\n",
					(unsigned long long)ip->i_ino, iip->ili_fields);
		}
		/* deadlock fix — raw un-take of the nowait flush ILOCK
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
		/* audited no-I/O completion (cluster flush abort) */
		xfs_buf_ioend_fail_unsubmitted(bp);
		return error;
	}

	if (!clcount)
		return -EAGAIN;

	/*
	 * before this cluster buffer is written, restore any FOREIGN
	 * directory inode's region from the durable on-disk image so a flush
	 * driven by a co-resident dirty CHILD cannot revert a peer's committed
	 * dir entries (PROVEN cross-inode cluster-buffer false-sharing).  This
	 * is the SAFE site noted below (buffer locked but not yet I/O-owned).
	 */
	mxfs_iflush_cluster_merge_dirs(bp);

	/*
	 * FIX ATTEMPT 2 (build 977C5A3E) REVERTED: the inode-cluster
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

/*
 * (design-consult ruling F2(b)): repair writer for a LAUNDERED publication
 * obligation — the inode log item reads clean while MXFS_IF_PUBOB is still
 * armed, i.e. a skip fence (P119 at non-EX, measured test10/test7) marked
 * the committed nlink=0 conversion clean without ever writing it, so the
 * home dinode still reads LINKED while the on-disk AGI list names it.  A
 * clean item cannot be flushed (xfs_iflush asserts ili_fields != 0), so
 * re-log the core in a tiny transaction — the same mechanism as the drain's
 * P146V arm — under i_mxfs_pipe_relog so xfs_trans_log_inode does NOT bump
 * pub_pending_seq (this represents no new committed change; bumping it made
 * the obligation unclosable — D-380).  The caller then flushes it through
 * the normal mandatory path: the copy-in snapshot equals pending, completion
 * advances durable to it, and the ledger closes on the real write.
 *
 * Runs in a DLM release kworker holding no XFS locks.  ILOCK is taken
 * nowait-EXCL with deadline backoff (a blocking xfs_ilock cannot be bounded
 * by a wall-clock deadline) and released with the raw un-take so the inline
 * BAST drain does not run inside the kworker executing the release.
 */
static int
mxfs_pubob_relog_core(
	struct xfs_inode	*ip,
	unsigned long		deadline)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	int			error;

	if (xfs_is_shutdown(mp))
		return -EIO;
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_ichange, 0, 0, 0, &tp);
	if (error)
		return error;
	while (!xfs_ilock_nowait(ip, XFS_ILOCK_EXCL)) {
		if (time_after(jiffies, deadline)) {
			xfs_trans_cancel(tp);
			mxfs_probe_ratelimited("mxfs: P87-TARGET-TIMEOUT ino=%llu stage=relog-ilock\n",
				(unsigned long long)ip->i_ino);
			return -ETIMEDOUT;
		}
		msleep(2);
	}
	/* Revalidate the repair authority under ILOCK EXCL. */
	if (VFS_I(ip)->i_nlink != 0 ||
	    !xfs_iflags_test(ip, MXFS_IF_PUBOB) ||
	    xfs_iflags_test(ip, XFS_ISTALE | XFS_IRECLAIM) ||
	    ip->i_mxfs_dead_incarn_gen) {
		xfs_trans_cancel(tp);
		error = -EINVAL;
		goto out_unlock;
	}
	xfs_trans_ijoin(tp, ip, 0);
	WRITE_ONCE(ip->i_mxfs_pipe_relog, 1);
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	error = xfs_trans_commit(tp);
	WRITE_ONCE(ip->i_mxfs_pipe_relog, 0);
	mxfs_probe_ratelimited("mxfs: P245-RELOG ino=%llu rc=%d pend=%llu dur=%llu dlm_mode=%u comm=%s — laundered obligation re-logged for the mandatory flush\n",
		(unsigned long long)ip->i_ino, error,
		(unsigned long long)ip->i_mxfs_pub_pending_seq,
		(unsigned long long)ip->i_mxfs_pub_durable_seq,
		(unsigned)ip->i_dlm_mode, current->comm);
out_unlock:
	WARN_ON_ONCE(atomic_dec_return(&ip->i_mxfs_ilk_wr_held) < 0);
	up_write(&ip->i_lock);
	return error;
}

/*
 * mandatory single-target inode flush for the AG-release publication
 * repair (P87, xfs_mxfs_dlm.c).  xfs_iflush_cluster is an opportunistic
 * scanner — every skip condition (ILOCK held, pinned, mid-flush) is legal for
 * it, which is exactly why the repair built on it converted 0-33% of splits
 * (measured: 3/3 tries lost to a local rm's ILOCK hold; the flush then ran
 * 14ms AFTER the unlock had published the split).  This helper makes the ONE
 * inode whose home-dinode conversion gates the publication MANDATORY: every
 * potentially-blocking stage is deadline-aware (design-consult ruling: a blocking
 * xfs_ilock cannot be bounded by a wall-clock deadline, so trylock+backoff),
 * lock order is ILOCK -> flush interlock -> cluster buffer, and the buffer
 * used is the one the inode log item is attached to (xfs_iflush asserts
 * li_buf == bp).
 *
 * Returns 0 when the inode's home conversion has been handed to a synchronous
 * buffer write (or the inode was already clean); -ENOENT when no identifiable
 * in-core inode exists (caller has no authority and must refuse, not guess);
 * -ETIMEDOUT when the deadline expired; -EAGAIN for xfs_iflush's transient
 * torn-shortform skip (caller may retry under its own deadline).
 *
 * Runs in the DLM release kworker holding no XFS locks.  The ILOCK is
 * released with the raw un-take (see the comment in
 * xfs_iflush_cluster): xfs_iunlock would run the inline BAST drain from
 * inside the very kworker that is executing the release.
 */
int
mxfs_iflush_agino_target(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	unsigned long		deadline)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_inode	*ip;
	struct xfs_inode_log_item *iip;
	struct xfs_buf		*bp = NULL;
	int			error = 0;
	bool			relogged = false;
	bool			had_sanction;

restart:
	rcu_read_lock();
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (!ip || ip->i_ino != xfs_agino_to_ino(pag, agino)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	spin_lock(&ip->i_flags_lock);
	if (ip->i_ino != xfs_agino_to_ino(pag, agino) ||
	    __xfs_iflags_test(ip, XFS_IRECLAIM | XFS_ISTALE)) {
		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();
		return -ENOENT;
	}
	if (__xfs_iflags_test(ip, XFS_IFLUSHING)) {
		/*
		 * A flush is already in flight; its buffer-write completion
		 * clears the flag.  Wait it out — the completed write may
		 * already be the conversion we need (caller re-reads the
		 * medium to decide).
		 */
		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();
		if (time_after(jiffies, deadline)) {
			mxfs_probe_ratelimited("mxfs: P87-TARGET-TIMEOUT ino=%llu stage=iflushing\n",
				(unsigned long long)xfs_agino_to_ino(pag, agino));
			return -ETIMEDOUT;
		}
		msleep(2);
		goto restart;
	}
	if (!xfs_ilock_nowait(ip, XFS_ILOCK_SHARED)) {
		struct task_struct *otsk = (struct task_struct *)
			(atomic_long_read(&ip->i_lock.owner) & ~0x7UL);

		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();
		if (time_after(jiffies, deadline)) {
			mxfs_probe_ratelimited("mxfs: P87-TARGET-TIMEOUT ino=%llu stage=ilock ocomm=%s opid=%d\n",
				(unsigned long long)xfs_agino_to_ino(pag, agino),
				otsk ? otsk->comm : "-",
				otsk ? task_pid_nr(otsk) : -1);
			return -ETIMEDOUT;
		}
		msleep(2);
		goto restart;
	}
	__xfs_iflags_set(ip, XFS_IFLUSHING);
	spin_unlock(&ip->i_flags_lock);
	rcu_read_unlock();

	/*
	 * ILOCK_SHARED + IFLUSHING held: no reclaim, no modification, no
	 * concurrent flush.  Revalidate the repair authority.
	 */
	if (xlog_is_shutdown(mp->m_log)) {
		error = -EIO;
		goto out_clear;
	}
	if (VFS_I(ip)->i_nlink != 0) {
		error = -EINVAL;
		goto out_clear;
	}

	/* Unpin, bounded: force this inode's commit seq, then poll. */
	while (xfs_ipincount(ip)) {
		xfs_log_force_inode(ip);
		if (!xfs_ipincount(ip))
			break;
		if (time_after(jiffies, deadline)) {
			mxfs_probe_ratelimited("mxfs: P87-TARGET-TIMEOUT ino=%llu stage=pin ipin=%d\n",
				(unsigned long long)ip->i_ino,
				xfs_ipincount(ip));
			error = -ETIMEDOUT;
			goto out_clear;
		}
		msleep(2);
	}

	if (xfs_inode_clean(ip)) {
		/*
		 * (design-consult ruling F2): a CLEAN item with the obligation
		 * still armed is a LAUNDERED conversion — P119 marked it clean
		 * without writing (measured: P245 rc=0 here while the home dinode
		 * kept reading nlink=1 for 60 audits).  Returning 0 misreported
		 * "converted".  Repair once: re-log the core (mxfs_pubob_relog_core)
		 * and restart so the mandatory path below writes it.  A second
		 * clean sighting with the flag still armed is reported honestly
		 * (-ENOMSG: nothing written) instead of laundered.
		 */
		if (xfs_iflags_test(ip, MXFS_IF_PUBOB) && !relogged) {
			xfs_iflags_clear(ip, XFS_IFLUSHING);
			atomic_dec(&ip->i_mxfs_ilk_rd_held);
			up_read(&ip->i_lock);
			error = mxfs_pubob_relog_core(ip, deadline);
			if (error) {
				mxfs_probe_ratelimited("mxfs: P245-RELOG-FAIL ino=%llu rc=%d\n",
					(unsigned long long)ip->i_ino, error);
				return error;
			}
			relogged = true;
			goto restart;
		}
		if (xfs_iflags_test(ip, MXFS_IF_PUBOB)) {
			mxfs_probe_ratelimited("mxfs: P245-CLEAN-MISMATCH ino=%llu — obligation armed, item clean after re-log; nothing written\n",
				(unsigned long long)ip->i_ino);
			error = -ENOMSG;
		}
		goto out_clear;	/* conversion already flushed; error == 0 */
	}

	iip = ip->i_itemp;
	spin_lock(&iip->ili_lock);
	bp = iip->ili_item.li_buf;
	if (bp)
		xfs_buf_hold(bp);
	spin_unlock(&iip->ili_lock);
	if (!bp) {
		/* Dirty with no attached cluster buffer: nothing this path
		 * can convert (attach-at-dirty invariant broken). */
		error = -ENODATA;
		goto out_clear;
	}

	/* Deadline-aware buffer lock, taken AFTER the ILOCK (correct order). */
	while (!xfs_buf_trylock(bp)) {
		if (time_after(jiffies, deadline)) {
			mxfs_probe_ratelimited("mxfs: P87-TARGET-TIMEOUT ino=%llu stage=buflock\n",
				(unsigned long long)ip->i_ino);
			xfs_buf_rele(bp);
			error = -ETIMEDOUT;
			goto out_clear;
		}
		msleep(2);
	}
	/* The attach can have changed while we waited for the lock. */
	if (xfs_inode_clean(ip)) {
		xfs_buf_relse(bp);
		goto out_clear;	/* a concurrent write finished the job */
	}
	if (ip->i_itemp != iip || iip->ili_item.li_buf != bp) {
		xfs_buf_relse(bp);
		if (time_after(jiffies, deadline)) {
			error = -ETIMEDOUT;
			goto out_clear;
		}
		xfs_iflags_clear(ip, XFS_IFLUSHING);
		atomic_dec(&ip->i_mxfs_ilk_rd_held);
		up_read(&ip->i_lock);
		msleep(2);
		goto restart;
	}

	/*
	 * the conversion of an OWNED obligation is sanctioned here
	 * regardless of the inode's current DLM mode — the AG-release audit
	 * reaches this helper after the inode release completed (NL), and
	 * without the sanction P119 would launder the just-re-logged item a
	 * second time (clean, no write, forever).  PUBOB is armed only by this
	 * node's own xfs_iunlink insert, so there is exactly one sanctioned
	 * writer for this inode+incarnation; the audit caller holds the AG EX
	 * (no list walker can run) and a peer cannot name an unlinked inode.
	 * Reldefer callers already hold the sanction; leave theirs alone.
	 */
	had_sanction = xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH);
	if (!had_sanction && xfs_iflags_test(ip, MXFS_IF_PUBOB))
		xfs_iflags_set(ip, MXFS_IF_DLM_RELFLUSH);
	else
		had_sanction = true;	/* nothing to undo below */
	error = xfs_iflush(ip, bp);
	if (!had_sanction)
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
	if (error == -EAGAIN) {
		/* Transient torn shortform (see xfs_iflush_cluster): leave the
		 * ILI dirty, let the caller retry under its deadline. */
		xfs_buf_relse(bp);
		goto out_clear;
	}
	if (error) {
		/*
		 * Mirror xfs_iflush_cluster's error path: shut down before
		 * failing the buffer so the log is dead first, and let the
		 * abort path own the IFLUSHING clear.
		 */
		xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		bp->b_flags |= XBF_ASYNC;
		/* audited no-I/O completion (cluster flush abort) */
		xfs_buf_ioend_fail_unsubmitted(bp);
		goto out_ilock;
	}

	/* Shared-LUN cluster write hygiene: restore foreign dir regions. */
	mxfs_iflush_cluster_merge_dirs(bp);
	error = xfs_bwrite(bp);
	xfs_buf_relse(bp);
	/* IFLUSHING is cleared by the write's completion (or its fail path). */
	goto out_ilock;

out_clear:
	xfs_iflags_clear(ip, XFS_IFLUSHING);
out_ilock:
	/* Raw un-take of the nowait ILOCK — no DLM ref was taken, and
	 * xfs_iunlock would run the inline BAST drain in THIS kworker. */
	atomic_dec(&ip->i_mxfs_ilk_rd_held);
	up_read(&ip->i_lock);
	return error;
}

/* Release an inode. */
void
xfs_irele(
	struct xfs_inode	*ip)
{
	trace_xfs_irele(ip, _RET_IP_);
	/* every XFS-side release lands in the reference-event ring. */
	mxfs_refev_rec(ip, _RET_IP_, 0);
	/*
	 * P205-REFBAL: MXFS releases with xfs_irele, NOT iput, so
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
	 * (D-AGI-UNLINKED F1): a cached FOREIGN zombie — nlink==0
	 * with no local-unlink intent and no recorded bucket membership — is a
	 * peer's live open-unlinked inode observed via lookup/adoption.  It is
	 * not on any of OUR lists and its bucket is not ours to walk or mutate
	 * (quotacheck/bulkstat arm of the defect).  Report success with no
	 * reload; the owner maintains its own list.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    ip->i_unlinked_bucket < 0 &&
	    !xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK)) {
		mxfs_probe_ratelimited(
		    "mxfs: P85-UNL-FOREIGN-RELOAD-SKIP ino=%llu agino=0x%x — foreign cached zombie; not walking a peer's bucket\n",
			(unsigned long long)ip->i_ino, agino);
		foundit = true;
		goto out_agibp;
	}

	/* walk the bucket this inode's entry actually lives in
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
