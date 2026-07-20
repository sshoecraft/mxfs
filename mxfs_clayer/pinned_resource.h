/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mxfs_clayer/pinned_resource.h — D9: pin-during-multi-step-op
 *
 * Multi-step operations under a single DLM token (e.g., directory create:
 * read parent → modify entries → flush → release) MUST pin the underlying
 * resource for the entire operation.  The BAST handler honors the pin
 * count: while pin > 0 the lock release is deferred even if a peer is
 * waiting (bounded by MXFS_BAST_YIELD_QUANTUM in yield_quantum.h).
 *
 * Spec §4 D9, §7.7.  Replaces the gap that was the canonical Mode A
 * failure (mxfs.1 Bug 49: 4 nodes × 200 files = 515/800 unique, 152
 * dupes — caused by DLM EX released between get_dir_mode and flush).
 *
 * Usage in directory operations (xfs_create/mkdir/link/rename/unlink):
 *   mxfs_inode_pin(parent_dp);
 *   ... whole op including trans_alloc/commit ...
 *   mxfs_inode_unpin(parent_dp);
 *
 * Pin nesting: pin_count is uint16_t; nested pins on the same inode add.
 * No deadlock concern because pin is just a counter, not a lock.
 *
 * Pin and the existing i_dlm_ex_holders / i_dlm_pr_holders are independent:
 * holders track per-ilock_begin/end pairs (kernel-XFS atomic-lock scope);
 * pin tracks per-multi-step-op (cluster-coherency scope).  Both must be
 * zero (and yield_remaining drained) for a deferred BAST to fire.
 */
#ifndef _MXFS_CLAYER_PINNED_RESOURCE_H
#define _MXFS_CLAYER_PINNED_RESOURCE_H

struct xfs_inode;

/*
 * Pin an inode for the duration of a multi-step DLM-coherent operation.
 * Increments i_dlm_pin_count under i_dlm_lock.  Safe to nest (counter
 * is additive).  Does NOT acquire any DLM token — caller must take
 * ilock the usual way; pin only governs BAST deferral.
 */
void mxfs_inode_pin(struct xfs_inode *ip);

/*
 * Release a pin.  Decrements i_dlm_pin_count under i_dlm_lock.  If this
 * decrement clears all conditions blocking a deferred BAST (pin and
 * holder counts == 0, yield quantum drained to 0), invokes the §7.2
 * release sequence inline (mxfs_dlm_bast_process).
 *
 * Bug 77 invariant: 1→0 transition MUST invoke release if a BAST is
 * deferred — never decrement and walk away.  See spec §4 D10.
 */
void mxfs_inode_unpin(struct xfs_inode *ip);

#endif /* _MXFS_CLAYER_PINNED_RESOURCE_H */
