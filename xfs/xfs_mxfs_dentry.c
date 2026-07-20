// SPDX-License-Identifier: GPL-2.0
/*
 * mxfs dentry_operations — d_revalidate for cluster coordination.
 *
 * Sess35 finding: upstream XFS does not define dentry_operations because
 * it's a single-node filesystem. mxfs inherited this gap. Cached dentry
 * lookups short-circuit through the VFS dcache without ever hitting
 * mxfs_dlm_ilock_begin → no DLM coordination → catastrophic Mode A
 * duplicate-create.
 *
 * Modeled on GFS2's gfs2_dops (fs/gfs2/dentry.c). On every cached
 * dentry lookup, d_revalidate takes the parent dir lock SHARED (which
 * routes through mxfs_dlm_ilock_begin → DLM grant), verifies the name
 * still resolves to the expected inode in the parent, returns 1 if
 * valid, 0 if not.
 *
 * If d_revalidate returns 0, VFS drops the dentry and re-does the
 * lookup via xfs_lookup → mxfs_dlm_ilock_begin → DLM coordination.
 */

#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_dir2.h"
#include "xfs_mxfs_dlm.h"
#include "xfs_trace.h"

#include <linux/dcache.h>
#include <linux/namei.h>

/*
 * mxfs_drevalidate — verify a cached dentry is still valid.
 *
 * Returns: 1 if valid, 0 if invalid (forces VFS re-lookup), -ECHILD
 * for RCU-walk (forces VFS to retry in ref-walk mode).
 */
static int
mxfs_drevalidate(struct inode *dir, const struct qstr *name,
		 struct dentry *dentry, unsigned int flags)
{
	struct xfs_inode	*dp;
	struct xfs_inode	*ip;
	struct xfs_name		xname;
	xfs_ino_t		actual_ino = 0;
	int			error;

	/*
	 * RCU-walk doesn't allow blocking. Return -ECHILD to force VFS
	 * to drop RCU and retry in ref-walk mode (where blocking is OK).
	 */
	if (flags & LOOKUP_RCU)
		return -ECHILD;

	if (!dir)
		return 1;
	dp = XFS_I(dir);

	if (!dentry)
		return 1;

	/*
	 * Single-node: no peer can change the parent behind us, so the
	 * dcache is authoritative.  Skip revalidation entirely to preserve
	 * single-node performance (this fires on every path-walk component).
	 */
	if (!dp->i_mount->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm))
		return 1;

	/* Synthesize xfs_name from qstr */
	xname.name = name->name;
	xname.len = name->len;
	xname.type = XFS_DIR3_FT_UNKNOWN;

	/*
	 * Acquire parent ILOCK SHARED — this routes through
	 * mxfs_dlm_ilock_begin and ensures we have a coordinated view of
	 * the parent dir (DLM grant + reload-if-stale).  Then look up the
	 * name to verify the cached dentry still matches the parent.
	 */
	xfs_ilock(dp, XFS_ILOCK_SHARED);
	error = xfs_dir_lookup(NULL, dp, &xname, &actual_ino, NULL, NULL);
	xfs_iunlock(dp, XFS_ILOCK_SHARED);

	pr_warn_once("mxfs: H37-MXFS-DREVALIDATE active\n");

	if (!d_really_is_positive(dentry)) {
		/*
		 * NEGATIVE dentry.  This is the cross-node create-race loser
		 * case: our cached "name does not exist" is stale because a
		 * peer created it (sess38).  If the coordinated lookup now
		 * finds the name, invalidate so the VFS re-resolves to the
		 * peer's inode; otherwise the negative is still valid.
		 */
		return error ? 1 : 0;
	}

	ip = XFS_I(d_inode(dentry));
	if (error) {
		/* Lookup failed — name no longer resolves. Drop dentry. */
		return 0;
	}
	if (actual_ino != ip->i_ino) {
		/* Name resolves to a DIFFERENT inode now — peer renamed
		 * or recreated. Drop dentry. */
		return 0;
	}

	/*
	 * ccloop cc87fed3 sess5 (RULE 4 — BUG3 hunt): this dentry is about to
	 * be approved as VALID based on inode NUMBER match only — actual_ino
	 * came from a fresh on-disk xfs_dir_lookup, but "valid" here only means
	 * "this cached ip is still the right number", never "this cached ip is
	 * the current, non-dying incarnation". If a peer freed+reused this
	 * exact inode number and this node's copy of ip is concurrently mid
	 * eviction (bast/reclaim path already tearing it down), a caller like
	 * filename_unlinkat will be handed a dying inode moments before its own
	 * ihold()/iput() pair — this is the exact mechanism suspected for BUG3
	 * (sess4's do_unlinkat/filename_unlinkat ihold-WARN-before-vfs_unlink
	 * breakthrough: i_count already <=0 at the caller's own protective
	 * ihold). Diagnostic only — verdict unchanged either way.
	 */
	{
		struct inode *vip = VFS_I(ip);
		unsigned long istate = READ_ONCE(vip->i_state);
		int icount = atomic_read(&vip->i_count);

		if (unlikely((istate & (I_FREEING | I_WILL_FREE | I_CLEAR | I_NEW)) ||
			     icount < 1)) {
			static atomic_t p133_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p133_n) <= 4000)
				pr_warn("mxfs: P133-DREVAL-DYING ino=%llu i_count=%d i_state=0x%lx dlm_mode=%u pid=%d comm=%s — d_revalidate about to approve a dying cached inode\n",
					(unsigned long long)ip->i_ino, icount,
					istate, (unsigned)ip->i_dlm_mode,
					current->pid, current->comm);
		}
	}
	return 1;
}

/*
 * mxfs_dentry_operations — install via sb->s_d_op in mount handler.
 *
 * d_hash and d_delete are inherited (NULL → defaults). Only
 * d_revalidate is needed for cluster coordination.
 */
const struct dentry_operations mxfs_dentry_operations = {
	.d_revalidate = mxfs_drevalidate,
};
