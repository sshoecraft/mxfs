// SPDX-License-Identifier: GPL-2.0
/*
 * mxfs_clayer/pinned_resource.c — D9 pin/unpin implementation.
 *
 * Pins are per-inode refcounts that the BAST handling path honors: while
 * pin_count > 0, a deferred BAST waits even after all i_dlm_ex/pr_holders
 * have drained.  Together with D10 yield quantum, this closes the Mode A
 * window where a multi-step op (e.g., xfs_create) had its parent-dir DLM
 * token stolen between the read-modify and flush steps.
 *
 * The release-trigger check on unpin is the §7.6 step 4 condition:
 *   bast_pending && pin_count == 0 && holders == 0 && yield_remaining == 0
 *
 * On 1→0 pin transition that satisfies the condition, this file invokes
 * mxfs_dlm_bast_process inline.  i_dlm_demoter is set across the call so
 * any same-thread re-entrant ilock_begin (writeback during page-cache
 * flush) takes the demoter fast path instead of self-deadlocking on the
 * DEMOTING wait.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_mxfs_dlm.h"
#include "yield_quantum.h"
#include "pinned_resource.h"

void
mxfs_inode_pin(
	struct xfs_inode	*ip)
{
	if (!ip)
		return;
	spin_lock(&ip->i_dlm_lock);
	ip->i_dlm_pin_count++;
	spin_unlock(&ip->i_dlm_lock);
}

void
mxfs_inode_unpin(
	struct xfs_inode	*ip)
{
	bool			need_release = false;
	unsigned long		sf_keep_j = 0;

	if (!ip)
		return;

	spin_lock(&ip->i_dlm_lock);
	if (WARN_ON_ONCE(ip->i_dlm_pin_count == 0)) {
		spin_unlock(&ip->i_dlm_lock);
		return;
	}
	ip->i_dlm_pin_count--;

	/*
	 * If a BAST was deferred while we were pinned, every put() (here,
	 * the unpin) decrements the yield quantum.  When pin, holders, AND
	 * yield_remaining all hit 0, fire the deferred release inline.
	 *
	 * Bug 77 (mxfs.1): the 1→0 transition MUST invoke release.  Failing
	 * to do so is exactly the failure mxfs.1 saw — quantum decrements
	 * but nobody else triggers release; thread polls; timeout fires.
	 */
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_BAST) {
		mxfs_yield_decrement(ip);

		if (ip->i_dlm_pin_count == 0 &&
		    ip->i_dlm_ex_holders == 0 &&
		    ip->i_dlm_pr_holders == 0 &&
		    ip->i_dlm_yield_remaining == 0) {
			/*
			 * sess1 (ccloop 46efd8b6) DIR-EX TENURE FLOOR: mirror
			 * of the ilock_end floor — a mid-op BAST on a YOUNG
			 * contended dir-EX tenure whose last quiescent
			 * transition is this unpin must not hand off yet
			 * (one-op-per-rotation collapse).  Revert to
			 * CACHED&&bast_pending; the armed dwork serves the
			 * peer at MHT window expiry.
			 */
			sf_keep_j = mxfs_dlm_dir_tenure_keep_delay(ip);
			if (sf_keep_j) {
				ip->i_dlm_bast_pending = true;
				ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
			} else {
				ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
				need_release = true;
			}
		}
	} else if (ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
		   ip->i_dlm_bast_pending &&
		   ip->i_dlm_pin_count == 0 &&
		   ip->i_dlm_ex_holders == 0 &&
		   ip->i_dlm_pr_holders == 0) {
		/*
		 * sess11(a9a03929): mirror of mxfs_dlm_ilock_end's sess9-v3
		 * CACHED&&bast_pending arm (with the sess11 consume).  A
		 * deferred BAST parked behind i_dlm_bast_pending (MHT
		 * batch_arm / gen-moved abort) whose tenure's LAST quiescent
		 * transition is an UNPIN — the common shape for create/mv/rm
		 * transactions, where iunlock precedes the trans-pin drop —
		 * was invisible here (this gate keyed only on state==BAST),
		 * so the tenure coasted to the MHT dwork expiry (~inode_mht_ms
		 * = 300ms) before the peer was served.  tcp_dlm_scaling
		 * measured 141/450 tenures on t1 coasting -> ~70s vs the 60s
		 * window (uniform on all 4 nodes).  Serve the peer at the
		 * first genuinely quiescent unpin instead; consume the flag
		 * (the release discharges the obligation).
		 *
		 * sess14(a9a03929) SF-DIR TENURE FLOOR: unless the tenure is
		 * still younger than dir_sf_mht_ms on a shortform dir — then
		 * keep the grant across this idle gap (the same node's next
		 * round op re-enters in ~2-5ms) and let the MHT dwork serve
		 * the peer at window expiry.  See
		 * mxfs_dlm_sf_tenure_keep_delay().
		 */
		/* sess1 (ccloop 46efd8b6): generalized to every dir format —
		 * see mxfs_dlm_dir_tenure_keep_delay (subsumes the sf floor). */
		sf_keep_j = mxfs_dlm_dir_tenure_keep_delay(ip);
		if (!sf_keep_j) {
			ip->i_dlm_bast_pending = false;
			ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
			need_release = true;
		}
	}
	spin_unlock(&ip->i_dlm_lock);

	if (sf_keep_j)
		mxfs_dlm_sf_tenure_arm(ip, sf_keep_j);

	if (need_release) {
		/*
		 * Same demoter dance as mxfs_dlm_ilock_end's inline path.
		 * bast_process flushes dirty pages → re-enters xfs_ilock
		 * via writeback (xfs_map_blocks); the recursive ilock_begin
		 * must skip the DEMOTING wait, which i_dlm_demoter == current
		 * achieves.
		 */
		ip->i_dlm_demoter = current;
		mxfs_dlm_bast_process(ip);
		ip->i_dlm_demoter = NULL;
	}
}
