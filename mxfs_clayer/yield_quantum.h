/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mxfs_clayer/yield_quantum.h — D10: BAST yield quantum
 *
 * When a BAST arrives on a token we hold, instead of releasing immediately
 * the local node may continue serving up to MXFS_BAST_YIELD_QUANTUM more
 * operations under the held token before honoring the BAST.  This
 * amortizes the cluster lock-bounce cost when N nodes are creating files
 * in the same directory: rather than 1 lock-bounce per file, each node
 * gets a burst of ~32 files per acquired token cycle.
 *
 * Spec §4 D10, §7.6 step 4.
 *
 * mxfs.1 Bug 77 caveat: implementation MUST guarantee the quantum
 * eventually expires — quantum 1→0 MUST trigger lock release (not just
 * decrement and walk away).  See mxfs_inode_unpin in pinned_resource.c
 * for the 1→0 release trigger.
 */
#ifndef _MXFS_CLAYER_YIELD_QUANTUM_H
#define _MXFS_CLAYER_YIELD_QUANTUM_H

struct xfs_inode;

/*
 * Default quantum size.  32 chosen per spec §4 D10 default.  Increasing
 * this raises per-node burst length but lengthens peer's worst-case
 * wait time on a contended lock.
 */
#define MXFS_BAST_YIELD_QUANTUM 32

/*
 * Arm the yield counter at MXFS_BAST_YIELD_QUANTUM.  Caller MUST hold
 * ip->i_dlm_lock.  Called from bast_notify when a BAST arrives on a
 * token we hold but cannot immediately release (pinned or has holders).
 */
void mxfs_yield_arm(struct xfs_inode *ip);

/*
 * Decrement the yield counter (saturating at 0).  Caller MUST hold
 * ip->i_dlm_lock.  Called from put() paths (ilock_end, unpin) while a
 * BAST is pending so the quantum drains as local ops finish.
 */
void mxfs_yield_decrement(struct xfs_inode *ip);

#endif /* _MXFS_CLAYER_YIELD_QUANTUM_H */
