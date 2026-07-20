/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mxfs_clayer/acquire.h — v6a acquire-token chokepoint (sess35 sketch)
 *
 * STATUS: SKETCH ONLY. Sess36+ implementation task.
 *
 * Per `docs/v6-cache-architecture-proposal.md` §3.3.
 *
 * Pairs with mxfs_clayer_release_token. ALL paths that acquire a DLM
 * token MUST go through this function. The fast-path "I have the token
 * cached" check goes through here, with epoch validation that prevents
 * the Mode A duplicate-create scenario where stale cached state in
 * the inode struct survives a peer's modification.
 */
#ifndef _MXFS_CLAYER_ACQUIRE_H
#define _MXFS_CLAYER_ACQUIRE_H

#include "release.h"  /* mxfs_clayer_token */

/*
 * mxfs_clayer_acquire_token — THE chokepoint.
 *
 * Per proposal §3.3:
 *
 *   1. mxfs_dlm_lock(t) — DLM grant first. After this returns, we hold
 *      the lock; no peer can modify until we release.
 *   2. If t->epoch == t->cached_epoch && t->cached_epoch != 0 → we
 *      held this token before and never released. Cache is still
 *      valid. Skip invalidation.
 *   3. Otherwise: invalidate. Per-resource:
 *        AG token   → mxfs_invalidate_ag(t->ag_no)
 *        INODE token → mxfs_invalidate_inode(t->ino)
 *   4. t->cached_epoch = t->epoch.
 *
 * Subsequent reads while we hold the token serve from page cache /
 * xfs_buf cache normally (page-cache amortized like GFS2 — no
 * FUA-on-every-read).
 *
 * Mode A specific: the ONLY way the in-memory inode's fast-path
 * cached state becomes "you have EX" is via this chokepoint.
 * Therefore there's no path for state=ICACHED+mode=EX to be set
 * without an actual CAW grant having happened.
 *
 * The current v5 ilock_begin fast-path (xfs_mxfs_dlm.c:1211-1264)
 * trusts ip->i_dlm_state and ip->i_dlm_mode without re-validating
 * against epoch. That's the leak point. v6a closes it by routing
 * EVERY acquire through this chokepoint, which validates epoch.
 *
 * Returns 0 on success or -errno on failure.
 */
int mxfs_clayer_acquire_token(struct mxfs_clayer_token *t);

#endif /* _MXFS_CLAYER_ACQUIRE_H */
