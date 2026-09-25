// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- per-task context: directory drains, recovery tasks and fallible acquires
 */
#define MXFS_TU_ID 14	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
static DEFINE_SPINLOCK(mxfs_dirdrain_lock);
static DEFINE_HASHTABLE(mxfs_dirdrain_hash, MXFS_DIRDRAIN_HASH_BITS);

void
mxfs_dirdrain_enter(struct mxfs_dirdrain_task *e)
{
	e->task = current;
	e->mode = MXFS_LOCK_NL;
	spin_lock(&mxfs_dirdrain_lock);
	hash_add(mxfs_dirdrain_hash, &e->node, (unsigned long)current);
	spin_unlock(&mxfs_dirdrain_lock);
}

void
mxfs_dirdrain_exit(struct mxfs_dirdrain_task *e)
{
	spin_lock(&mxfs_dirdrain_lock);
	hash_del(&e->node);
	spin_unlock(&mxfs_dirdrain_lock);
}

/* Stamp the innermost active bracket of this task with the outgoing held
 * mode.  No-op when the caller was not bracketed (fail-safe: unsanctioned). */
void
mxfs_dirdrain_set_mode(uint8_t mode)
{
	struct mxfs_dirdrain_task *e;

	spin_lock(&mxfs_dirdrain_lock);
	hash_for_each_possible(mxfs_dirdrain_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current) {
			e->mode = mode;
			break;
		}
	}
	spin_unlock(&mxfs_dirdrain_lock);
}

/* Fence query (xfs_buf_submit_ex): is the current task a sanctioned
 * EX-tenure release drain?  Any active bracket at EX sanctions (nesting:
 * an inner PR bracket does not revoke an outer EX one — the task is still
 * inside the outer EX drain). */
bool
mxfs_task_in_dir_drain(void)
{
	struct mxfs_dirdrain_task *e;
	bool sanctioned = false;

	spin_lock(&mxfs_dirdrain_lock);
	hash_for_each_possible(mxfs_dirdrain_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current && e->mode == MXFS_LOCK_EX) {
			sanctioned = true;
			break;
		}
	}
	spin_unlock(&mxfs_dirdrain_lock);
	return sanctioned;
}

static DEFINE_SPINLOCK(mxfs_recovtask_lock);
static DEFINE_HASHTABLE(mxfs_recovtask_hash, 4);

void
mxfs_recovtask_enter(struct mxfs_recovtask *e, uint8_t phase)
{
	e->task = current;
	e->phase = phase;
	spin_lock(&mxfs_recovtask_lock);
	hash_add(mxfs_recovtask_hash, &e->node, (unsigned long)current);
	spin_unlock(&mxfs_recovtask_lock);
}

void
mxfs_recovtask_exit(struct mxfs_recovtask *e)
{
	spin_lock(&mxfs_recovtask_lock);
	hash_del(&e->node);
	spin_unlock(&mxfs_recovtask_lock);
}

void
mxfs_recovtask_set_phase(uint8_t phase)
{
	struct mxfs_recovtask *e;

	spin_lock(&mxfs_recovtask_lock);
	hash_for_each_possible(mxfs_recovtask_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current) {
			e->phase = phase;
			break;
		}
	}
	spin_unlock(&mxfs_recovtask_lock);
}

static DEFINE_SPINLOCK(mxfs_acqfall_lock);
static DEFINE_HASHTABLE(mxfs_acqfall_hash, 4);

static void
mxfs_acqfall_enter_kind(struct mxfs_acqfallible *e, u64 id, bool ag)
{
	e->task = current;
	e->ino = id;
	e->ag = ag;
	e->gave_up = false;
	e->rc = 0;
	spin_lock(&mxfs_acqfall_lock);
	hash_add(mxfs_acqfall_hash, &e->node, (unsigned long)current);
	spin_unlock(&mxfs_acqfall_lock);
}

void
mxfs_acqfall_enter(struct mxfs_acqfallible *e, u64 ino)
{
	mxfs_acqfall_enter_kind(e, ino, false);
}

void
mxfs_acqfall_exit(struct mxfs_acqfallible *e)
{
	spin_lock(&mxfs_acqfall_lock);
	hash_del(&e->node);
	spin_unlock(&mxfs_acqfall_lock);
}

/* Is the current task's acquire of THIS inode allowed to fail instead of
 * waiting?  The innermost registration for the inode answers. */
bool
mxfs_acqfall_armed_for(u64 ino)
{
	struct mxfs_acqfallible *e;
	bool armed = false;

	spin_lock(&mxfs_acqfall_lock);
	hash_for_each_possible(mxfs_acqfall_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current && !e->ag && e->ino == ino) {
			armed = true;
			break;
		}
	}
	spin_unlock(&mxfs_acqfall_lock);
	return armed;
}

/* The DLM engine's question (acq_fallible_cb), for a killed task. */
int
mxfs_acq_task_fallible_for(uint64_t ino)
{
	return mxfs_acqfall_armed_for(ino) ? 1 : 0;
}

/* 0.84.5: the same question for an AG acquire the task registered. */
int
mxfs_acq_task_fallible_for_ag(uint32_t agno)
{
	struct mxfs_acqfallible *e;
	bool armed = false;

	spin_lock(&mxfs_acqfall_lock);
	hash_for_each_possible(mxfs_acqfall_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current && e->ag && e->ino == agno) {
			armed = true;
			break;
		}
	}
	spin_unlock(&mxfs_acqfall_lock);
	return armed ? 1 : 0;
}

/*
 * 0.84.5 (D-...-0960): the untrusted iget's AG acquire, at a boundary when
 * the task may already fail the inode it is looking up (the mount's root
 * inode: registered by mxfs_iget_root_fallible).  A stalled authority
 * transition then ends the acquire with -EREMCHG instead of waiting for
 * ever, and the lookup fails; for any other task this is the plain
 * blocking acquire.
 */
int
mxfs_ag_dlm_lock_fallible_for(struct xfs_mount *mp, struct xfs_perag *pag,
			      u64 ino)
{
	struct mxfs_acqfallible	acqfall;
	int			error;

	if (!mxfs_acqfall_armed_for(ino))
		return mxfs_ag_dlm_lock(mp, pag);
	mxfs_acqfall_enter_kind(&acqfall, pag_agno(pag), true);
	error = mxfs_ag_dlm_lock(mp, pag);
	mxfs_acqfall_exit(&acqfall);
	if (error == -EREMCHG)
		pr_warn(
		    "mxfs: P960-AUTH-TRANSITION-FAIL ino=%llu ag=%u mode=%u laps=0 mounting=%d comm=%s — the takeover this AG acquire waits on stalled; failing THIS lookup with -EREMCHG, not the mount, and not shutting down\n",
			(unsigned long long)ino, pag_agno(pag), MXFS_LOCK_EX,
			(!mp->m_super || !mp->m_super->s_root) ? 1 : 0,
			current->comm);
	return error;
}

/*
 * 0.89.69: the SB summary lock's acquire, registered for the summary key so
 * a stalled page transition fails it (-EREMCHG) instead of waiting for ever;
 * see mxfs_sb_summary_lock for why every caller can take that.
 */
int
mxfs_sb_summary_lock_fallible(struct xfs_mount *mp, uint64_t key,
			      struct mxfs_grant_result *gres)
{
	struct mxfs_acqfallible	acqfall;
	int			rc;

	mxfs_acqfall_enter(&acqfall, key);
	rc = mxfs_v5_dlm_inode_lock(mp->m_mxfs_dlm, key, MXFS_LOCK_EX, gres);
	mxfs_acqfall_exit(&acqfall);
	if (rc == -EREMCHG)
		pr_warn("mxfs: P960-AUTH-TRANSITION-FAIL-SB slot=%u key=%llu rc=%d comm=%s — the takeover the SB summary lock waited on stalled; failing THIS lock (the caller covers nothing and never writes the SB unlocked), not the mount\n",
			mp->m_mxfs_node_slot, (unsigned long long)key, rc,
			current->comm);
	return rc;
}

/*
 * 0.84.5 (D-...-0960): the mount's root inode lookup as a fallible boundary
 * — nothing dirty, no transaction, the mount not yet published.  The AG
 * acquire inside the untrusted iget and the inode lock after it may both be
 * refused; either refusal fails the MOUNT through its ordinary unwind.
 */
int
mxfs_iget_root_fallible(struct xfs_mount *mp, xfs_ino_t ino,
			struct xfs_inode **ipp)
{
	struct mxfs_acqfallible	acqfall;
	int			error;

	mxfs_acqfall_enter(&acqfall, ino);
	error = xfs_iget(mp, NULL, ino, XFS_IGET_UNTRUSTED, 0, ipp);
	mxfs_acqfall_exit(&acqfall);
	if (error)
		return error;
	error = mxfs_ilock_fallible(*ipp, XFS_ILOCK_EXCL);
	if (error) {
		xfs_irele(*ipp);
		*ipp = NULL;
	}
	return error;
}

/* The hook's verdict: this acquire is being abandoned, fail the operation
 * with `rc` (0.84.5: -EIO for an abandoned wait, -EAGAIN for a stalled
 * authority transition — the caller may simply try again later). */
void
mxfs_acqfall_give_up_rc(u64 ino, int rc)
{
	struct mxfs_acqfallible *e;

	spin_lock(&mxfs_acqfall_lock);
	hash_for_each_possible(mxfs_acqfall_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current && !e->ag && e->ino == ino) {
			e->gave_up = true;
			e->rc = rc;
			break;
		}
	}
	spin_unlock(&mxfs_acqfall_lock);
}

void
mxfs_acqfall_give_up(u64 ino)
{
	mxfs_acqfall_give_up_rc(ino, -EIO);
}

/* Read and clear, so a caller that retries starts from a clean verdict.
 * *rc receives the errno the give-up named (valid only when true). */
bool
mxfs_acqfall_taken(struct mxfs_acqfallible *e, int *rc)
{
	bool gave_up = e->gave_up;

	if (rc && gave_up)
		*rc = e->rc ? e->rc : -EIO;
	e->gave_up = false;
	e->rc = 0;
	return gave_up;
}

/*
 * 0.84.13: PEEK, from inside an audited call, at whether the current
 * task's registered acquire of this inode has already been refused.  The
 * lookup registers the directory around xfs_dir_lookup, whose own
 * xfs_ilock_data_map_shared carries the acquire; when that acquire gave
 * up the local lock is still taken (xfs_ilock returns void) and the lookup
 * would go on to read directory blocks under no grant — a stale image
 * cached as current.  So the lookup asks here, right after its lock, and
 * returns before it reads anything; the verdict is read and cleared by the
 * registering caller, not by this peek.
 */
bool
mxfs_acqfall_refused(u64 ino)
{
	struct mxfs_acqfallible *e;
	bool refused = false;

	spin_lock(&mxfs_acqfall_lock);
	hash_for_each_possible(mxfs_acqfall_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current && !e->ag && e->ino == ino) {
			refused = e->gave_up;
			break;
		}
	}
	spin_unlock(&mxfs_acqfall_lock);
	return refused;
}
EXPORT_SYMBOL(mxfs_acqfall_refused);

/*
 * THE EXPLICIT, ERROR-RETURNING ACQUIRE for an audited call site.
 *
 * xfs_ilock returns void and always takes the local lock components it is
 * asked for; the cluster grant underneath it is what can fail.  A caller
 * converted to this interface gets the answer at the acquisition itself,
 * before it touches any state the grant protects: 0 with every component of
 * `flags` held and the grant established, or -EIO (or -EINTR for a killed
 * task) with every component of `flags` released again — exactly the ones
 * this call took, nothing it did not.  Only the named inode may give up;
 * nested acquires of other inodes inside the ride wait as they always did.
 *
 * Audited sites: open (mxfs_dlm_open_protect, its own ride), getattr, and
 * the read path (the coherency envelope and the IOLOCK ride).  Each sits
 * where nothing is dirty and no transaction is open.
 */
int
mxfs_ilock_fallible(struct xfs_inode *ip, uint flags)
{
	struct mxfs_acqfallible	acqfall;
	int			ret = 0, rc = 0;

	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	xfs_ilock(ip, flags);
	if (mxfs_acqfall_taken(&acqfall, &rc)) {
		/*
		 * 0.87.23: the begin hook installed nothing for a request that
		 * gave up (it reset the inode to NONE and returned), so no DLM
		 * end is owed for these components — an end here found no
		 * holder and printed P71-UNDERFLOW on every give-up.
		 */
		xfs_iunlock(ip, flags | XFS_ILOCK_MXFS_NOEND);
		ret = fatal_signal_pending(current) ? -EINTR : rc;
	}
	mxfs_acqfall_exit(&acqfall);
	return ret;
}

/*
 * 0.84.4: readdir is an audited site — nothing dirty, no transaction, the
 * VFS holds only the directory's i_rwsem — and it acquires the directory's
 * cluster lock at up to four places (the consumer refresh, the shortform
 * outer lock, the format dispatch, and once per data block of a leaf
 * listing), each of which may now be refused.  One line names the stage so
 * a lap can say WHICH acquire the fault met.
 */
int
mxfs_readdir_refused(struct xfs_inode *dp, const char *stage, int rc)
{
	pr_warn_ratelimited(
	    "mxfs: P958-READDIR-REFUSED ino=%llu stage=%s rc=%d comm=%s — readdir refused: the cluster acquire was abandoned; failing the listing instead of waiting on it\n",
		(unsigned long long)dp->i_ino, stage, rc, current->comm);
	return rc;
}

/*
 * 0.84.13: the lookup is an audited site.  Nothing is dirty and no
 * transaction is open; the VFS holds the parent's i_rwsem and a refused
 * lookup fails the path walk with the refusal's errno, which is what every
 * syscall that resolves a name reports.  Two acquires: the consumer refresh
 * (stage=refresh) and the directory read inside xfs_dir_lookup (stage=dir),
 * which asks mxfs_acqfall_refused right after its lock so a refused acquire
 * reads no directory block.
 */
int
mxfs_lookup_refused(struct xfs_inode *dp, const char *stage, int rc)
{
	pr_warn_ratelimited(
	    "mxfs: P958-LOOKUP-REFUSED ino=%llu stage=%s rc=%d comm=%s — lookup refused: the directory's cluster acquire was abandoned; failing the name resolution instead of waiting on it\n",
		(unsigned long long)dp->i_ino, stage, rc, current->comm);
	return rc;
}

/*
 * 0.84.14: the write path's timestamp update.  A direct write whose data
 * grant is a cached PR fast-paths its shared IOLOCK ride and then, inside
 * kiocb_modified, xfs_vn_update_time takes ILOCK_EXCL — a cluster EX in a
 * transaction that is reserved and clean with nothing joined.  Measured
 * (s596d) as the first request such a write sends, so it is the acquire a
 * discarded request meets.  Register the inode around the call: the acquire
 * gives up at its budget, xfs_vn_update_time asks mxfs_acqfall_refused after
 * its lock and cancels the clean reservation, and the verdict is reported
 * here with the write's own stage name.
 */
int
mxfs_kiocb_modified_fallible(struct kiocb *iocb)
{
	struct file		*file = iocb->ki_filp;
	struct xfs_inode	*ip = XFS_I(file_inode(file));
	struct mxfs_acqfallible	acqfall;
	int			error, rc = 0;

	/*
	 * kiocb_modified for a blocking iocb is file_remove_privs then
	 * file_update_time.  Only the second is registered: the setuid strip
	 * runs a setattr and possibly an xattr removal, each with its own
	 * transaction and ilock and no peek, so a refused acquire under them
	 * would proceed on a local lock with no grant.  They wait, as before.
	 */
	error = file_remove_privs(file);
	if (error)
		return error;
	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	error = file_update_time(file);
	if (mxfs_acqfall_taken(&acqfall, &rc)) {
		error = fatal_signal_pending(current) ? -EINTR : rc;
		pr_warn_ratelimited(
		    "mxfs: P958-WRITE-REFUSED ino=%llu stage=timestamp mode=excl rc=%d comm=%s — write refused: the cluster acquire was abandoned; failing the write with nothing held instead of waiting on it\n",
			(unsigned long long)ip->i_ino, error, current->comm);
	}
	mxfs_acqfall_exit(&acqfall);
	return error;
}
EXPORT_SYMBOL(mxfs_kiocb_modified_fallible);

/*
 * 0.84.15: the attribute-change transaction (chmod, chown, utimensat) as an
 * audited boundary.  xfs_trans_alloc_ichange reserves tr_ichange, takes
 * ILOCK_EXCL — a cluster EX — and only then joins the inode and reserves
 * quota, so that acquire is the first request the change sends and the
 * reservation behind it is clean with nothing joined.  Register the inode
 * around the call: the acquire gives up at its budget, the allocator asks
 * mxfs_acqfall_refused right after its lock and cancels the reservation, and
 * the verdict is reported here with the operation's name.  The dquots the
 * caller allocated before the transaction are released on its own error
 * path, exactly as for any other allocation failure.
 */
int
mxfs_trans_alloc_ichange_fallible(struct xfs_inode *ip, struct xfs_dquot *udqp,
				  struct xfs_dquot *gdqp, struct xfs_dquot *pdqp,
				  bool force, struct xfs_trans **tpp,
				  const char *op)
{
	struct mxfs_acqfallible	acqfall;
	int			error, rc = 0;

	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	error = xfs_trans_alloc_ichange(ip, udqp, gdqp, pdqp, force, tpp);
	if (mxfs_acqfall_taken(&acqfall, &rc)) {
		error = fatal_signal_pending(current) ? -EINTR : rc;
		pr_warn_ratelimited(
		    "mxfs: P958-SETATTR-REFUSED ino=%llu op=%s rc=%d comm=%s — attribute change refused: the cluster acquire was abandoned; the clean reservation is cancelled instead of waiting on it\n",
			(unsigned long long)ip->i_ino, op, error, current->comm);
	}
	mxfs_acqfall_exit(&acqfall);
	return error;
}
EXPORT_SYMBOL(mxfs_trans_alloc_ichange_fallible);

/*
 * 0.84.20: the extended-attribute CHANGE (setxattr, removexattr, the
 * security init of a new inode) as an audited boundary.  xfs_attr_set reserves its transaction through
 * xfs_trans_alloc_inode — and, for an inode with no attr fork yet, first
 * runs xfs_attr_add_fork's own reservation the same way — so the ILOCK_EXCL
 * inside that allocator is the change's first request, taken on a
 * reservation that is clean with nothing joined.  Register the inode around
 * the allocator only: the allocator asks mxfs_acqfall_refused right after
 * its lock and cancels the reservation, and the verdict is reported here
 * with the change's stage (addfork, set, remove).  The transaction body
 * that follows a granted acquire holds ILOCK_EXCL throughout and takes no
 * further acquire of this inode, so nothing after the boundary can be
 * refused.
 */
int
mxfs_attr_trans_alloc_fallible(struct xfs_inode *ip, struct xfs_trans_res *resv,
			       unsigned int dblocks, unsigned int rblocks,
			       bool force, struct xfs_trans **tpp,
			       const char *stage)
{
	struct mxfs_acqfallible	acqfall;
	int			error, rc = 0;

	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	error = xfs_trans_alloc_inode(ip, resv, dblocks, rblocks, force, tpp);
	if (mxfs_acqfall_taken(&acqfall, &rc)) {
		error = fatal_signal_pending(current) ? -EINTR : rc;
		pr_warn_ratelimited(
		    "mxfs: P958-XATTRSET-REFUSED ino=%llu stage=%s rc=%d comm=%s — extended-attribute change refused: the cluster acquire was abandoned; the clean reservation is cancelled instead of waiting on it\n",
			(unsigned long long)ip->i_ino, stage, error, current->comm);
	}
	mxfs_acqfall_exit(&acqfall);
	return error;
}
EXPORT_SYMBOL(mxfs_attr_trans_alloc_fallible);

/*
 * 0.84.21: the page fault as an audited boundary — the ruling's separate
 * case, because its failure is VM_FAULT_SIGBUS to the faulting task rather
 * than an errno.  A read fault takes a counted PR hold directly
 * (mxfs_dlm_ilock_begin, not xfs_ilock) before filemap_fault; a write
 * fault first updates the timestamps (file_update_time ->
 * xfs_vn_update_time, ILOCK_EXCL in a reserved clean transaction) and then
 * takes a counted EX hold before iomap_page_mkwrite.  Each of those is
 * taken with no folio locked, nothing dirty and no transaction joined, so a
 * refusal leaves nothing to undo beyond the hold itself: the hook's end is
 * called for a begin that installed nothing, exactly as xfs_iunlock does
 * for every other fallible site, and the fault returns SIGBUS.  The nested
 * xfs_ilock inside the iomap path rides the counted hold and sends no
 * request of its own.
 */
int
mxfs_dlm_ilock_begin_fallible(struct xfs_inode *ip, uint8_t mode)
{
	struct mxfs_acqfallible	acqfall;
	int			ret = 0, rc = 0;

	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	mxfs_dlm_ilock_begin(ip, mode);
	if (mxfs_acqfall_taken(&acqfall, &rc)) {
		mxfs_dlm_ilock_end(ip, mode);
		ret = fatal_signal_pending(current) ? -EINTR : rc;
	}
	mxfs_acqfall_exit(&acqfall);
	/*
	 * -EAGAIN names a stalled authority transition, not a lost request;
	 * an errno caller may simply try again later, but a fault has no
	 * retry, so it waits it out exactly as an unregistered caller does.
	 */
	if (ret == -EAGAIN) {
		mxfs_dlm_ilock_begin(ip, mode);
		ret = 0;
	}
	return ret;
}

int
mxfs_fault_update_time_fallible(struct file *file)
{
	struct xfs_inode	*ip = XFS_I(file_inode(file));
	struct mxfs_acqfallible	acqfall;
	int			error, rc = 0;

	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	error = file_update_time(file);
	if (mxfs_acqfall_taken(&acqfall, &rc))
		error = fatal_signal_pending(current) ? -EINTR : rc;
	else
		error = 0;	/* upstream ignores a timestamp failure here */
	mxfs_acqfall_exit(&acqfall);
	/* A stalled authority transition: the update was cancelled clean
	 * (as any failed timestamp update is ignored here); the hold that
	 * follows waits it out. */
	if (error == -EAGAIN)
		error = 0;
	return error;
}

int
mxfs_fault_refused(struct xfs_inode *ip, const char *stage, int rc)
{
	pr_warn_ratelimited(
	    "mxfs: P958-FAULT-REFUSED ino=%llu stage=%s rc=%d comm=%s — page fault refused: the cluster acquire was abandoned; SIGBUS to the faulting task instead of waiting on it\n",
		(unsigned long long)ip->i_ino, stage, rc, current->comm);
	return rc;
}
EXPORT_SYMBOL(mxfs_dlm_ilock_begin_fallible);
EXPORT_SYMBOL(mxfs_fault_update_time_fallible);
EXPORT_SYMBOL(mxfs_fault_refused);

int
mxfs_dir_lookup_fallible(struct xfs_inode *dp, const struct xfs_name *name,
			 xfs_ino_t *inum, struct xfs_name *ci_name,
			 uint8_t *ftypep)
{
	struct mxfs_acqfallible	acqfall;
	int			error, rc = 0;

	mxfs_acqfall_enter(&acqfall, dp->i_ino);
	error = xfs_dir_lookup(NULL, dp, name, inum, ci_name, ftypep);
	if (mxfs_acqfall_taken(&acqfall, &rc))
		error = mxfs_lookup_refused(dp, "dir",
				fatal_signal_pending(current) ? -EINTR : rc);
	mxfs_acqfall_exit(&acqfall);
	return error;
}

/*
 * 0.84.11: a namespace operation (create, mkdir) is an audited site at its
 * FIRST cluster acquire — the parent directory's exclusive lock, taken after
 * the transaction has been reserved and before anything is allocated, logged
 * or joined.  A refusal there cancels a clean reservation through the
 * operation's ordinary error path and fails the syscall with the refusal's
 * errno; it never cancels a dirty transaction, which is not an undo.  One
 * line names the operation so a lap can say which acquire the fault met.
 */
/*
 * 0.84.19: the extended-attribute READ is an audited site.  xfs_attr_get and
 * xfs_attr_list take the attr-fork lock themselves, hold no transaction and
 * have nothing dirty, and every caller of theirs returns the error: getxattr
 * and listxattr to userspace; the capability read inside truncate, write
 * and setattr reads as "nothing to strip" and the operation goes on to its
 * own acquire; exec fails.  (POSIX ACLs and the handle ioctls are not
 * compiled into this module — xfs_acl.o and xfs_handle.o are excluded in
 * Kbuild — so there is no ACL read on a permission check.)  Measured (s601g)
 * as the FIRST acquire an ftruncate through a held fd sends, ahead of the
 * size transaction, so it was the acquire a discarded request met there.
 */
int
mxfs_xattr_refused(struct xfs_inode *ip, const char *op, int rc)
{
	pr_warn_ratelimited(
	    "mxfs: P958-XATTR-REFUSED ino=%llu op=%s rc=%d comm=%s — extended-attribute read refused: the cluster acquire was abandoned; failing the read with nothing held instead of waiting on it\n",
		(unsigned long long)ip->i_ino, op, rc, current->comm);
	return rc;
}
EXPORT_SYMBOL(mxfs_xattr_refused);

int
mxfs_namespace_refused(struct xfs_inode *dp, const char *op, int rc)
{
	pr_warn_ratelimited(
	    "mxfs: P958-NAMESPACE-REFUSED op=%s ino=%llu rc=%d comm=%s — %s refused: the directory's cluster acquire was abandoned; cancelling the clean reservation and failing the operation instead of waiting on it\n",
		op, (unsigned long long)dp->i_ino, rc, current->comm, op);
	return rc;
}

/*
 * 0.84.11: the SET forms.  remove and link take their first acquire as a
 * pair (the directory and the child, xfs_lock_two_inodes inside
 * xfs_trans_alloc_dir), rename as two to five (xfs_lock_inodes); at both
 * the transaction is reserved and clean and nothing is joined.  Every
 * distinct member is registered for the duration of the set acquire, so
 * any of them may give up.  A member that gave up does not stop the
 * remaining members' acquires — they wait exactly as they always did, and
 * the set helpers' own ordering, ABBA breaker and rwsem retry loops run
 * unchanged — so a refusal costs at most one budget per faulted member.
 * The verdicts are read after the set is taken; on any refusal the whole
 * set is released again (an unlock after a given-up acquire is the same
 * balance mxfs_ilock_fallible relies on) and the first refusal's errno is
 * returned with nothing held.
 */
int
mxfs_lock_two_inodes_fallible(struct xfs_inode *ip0, uint ip0_mode,
			      struct xfs_inode *ip1, uint ip1_mode)
{
	struct mxfs_acqfallible	f0, f1;
	int			rc0 = 0, rc1 = 0, ret = 0;
	bool			g0, g1;

	mxfs_acqfall_enter(&f0, ip0->i_ino);
	mxfs_acqfall_enter(&f1, ip1->i_ino);
	xfs_lock_two_inodes(ip0, ip0_mode, ip1, ip1_mode);
	g0 = mxfs_acqfall_taken(&f0, &rc0);
	g1 = mxfs_acqfall_taken(&f1, &rc1);
	mxfs_acqfall_exit(&f1);
	mxfs_acqfall_exit(&f0);
	if (g0 || g1) {
		xfs_iunlock(ip1, ip1_mode);
		xfs_iunlock(ip0, ip0_mode);
		ret = fatal_signal_pending(current) ? -EINTR : (g0 ? rc0 : rc1);
	}
	return ret;
}

int
mxfs_lock_inodes_fallible(struct xfs_inode **ips, int n, uint lock_mode)
{
	struct mxfs_acqfallible	f[5];
	int			i, ret = 0;

	if (n > 5)
		n = 5;
	for (i = 0; i < n; i++) {
		if (!ips[i] || (i && ips[i] == ips[i - 1]))
			continue;
		mxfs_acqfall_enter(&f[i], ips[i]->i_ino);
	}
	xfs_lock_inodes(ips, n, lock_mode);
	for (i = 0; i < n; i++) {
		int frc = 0;

		if (!ips[i] || (i && ips[i] == ips[i - 1]))
			continue;
		if (mxfs_acqfall_taken(&f[i], &frc) && !ret)
			ret = frc;
		mxfs_acqfall_exit(&f[i]);
	}
	if (ret) {
		for (i = n - 1; i >= 0; i--) {
			if (!ips[i] || (i && ips[i] == ips[i - 1]))
				continue;
			xfs_iunlock(ips[i], lock_mode);
		}
		if (fatal_signal_pending(current))
			ret = -EINTR;
	}
	return ret;
}

/* 0 = current task is not in recovery context. */
uint8_t
mxfs_task_recovery_phase(void)
{
	struct mxfs_recovtask *e;
	uint8_t phase = 0;

	spin_lock(&mxfs_recovtask_lock);
	hash_for_each_possible(mxfs_recovtask_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current) {
			phase = e->phase;
			break;
		}
	}
	spin_unlock(&mxfs_recovtask_lock);
	return phase;
}
