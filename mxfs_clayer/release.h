/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mxfs_clayer/release.h — v6a release-token chokepoint (sess35 sketch)
 *
 * STATUS: SKETCH ONLY. Sess36+ implementation task.
 *
 * Per `docs/v6-cache-architecture-proposal.md` §3.3.
 *
 * The chokepoint that closes Mode A by construction. ALL paths that
 * release a DLM token MUST go through this function. There is no
 * alternative release path.
 *
 * Replaces the scattered v5 release sites:
 *   - mxfs_dlm_bast_process (xfs/xfs_mxfs_dlm.c:558)
 *   - bast_notify NO_INODE branch (xfs/xfs_mxfs_dlm.c:618) — must
 *     synthesize a temporary state to drive the full sequence
 *   - bast_notify NONE_NL branch (xfs/xfs_mxfs_dlm.c:657) — same
 *   - mxfs_dlm_evict (xfs/xfs_mxfs_dlm.c:1594)
 *   - AG-token release paths in xfs/xfs_mxfs_dlm.c::mxfs_ag_dlm_unlock
 *
 * Migration plan:
 *   1. Implement this primitive.
 *   2. Migrate one release site at a time, verify with sess35_capture.sh.
 *   3. Once all sites use the chokepoint, remove the per-site invalidations.
 *
 * The Mode A bug doesn't return because there's nowhere else for the
 * release path to go.
 */
#ifndef _MXFS_CLAYER_RELEASE_H
#define _MXFS_CLAYER_RELEASE_H

#include <linux/types.h>

struct xfs_mount;

/*
 * Resource kinds for the chokepoint.
 */
enum mxfs_clayer_resource_kind {
	MXFS_CLAYER_RES_AG,
	MXFS_CLAYER_RES_INODE,
};

/*
 * mxfs_clayer_token: opaque handle to a held DLM token.
 *
 * Sess36 design: this should be allocated lazily at acquire time,
 * tracked per-mount (or per-inode for inode tokens), and freed at
 * release. Carries the resource kind, the AG number or inode number,
 * and the epoch (for cache-validity checks).
 */
struct mxfs_clayer_token {
	struct xfs_mount *mp;
	enum mxfs_clayer_resource_kind kind;
	union {
		xfs_agnumber_t ag_no;
		uint64_t       ino;
	};
	uint64_t epoch;          /* for invalidate-skip-if-still-current */
	uint64_t cached_epoch;   /* see proposal §3.3 acquire path */
};

/*
 * mxfs_clayer_release_token — THE chokepoint.
 *
 * Per proposal §3.3:
 *
 *   1. Per-resource AIL drain (mxfs_ail_push_ag_sync or per-inode equivalent)
 *   2. xfs_log_force(mp, XFS_LOG_SYNC) — global for v6a phase 1
 *   3. blkdev_issue_flush(mp->m_ddev_targp->bt_bdev)
 *   4. mxfs_invalidate_ag/inode (drop local cache)
 *   5. mxfs_dlm_unlock (the actual DLM call)
 *
 * Returns 0 on success or -errno.
 *
 * Sess35 evidence: the bug sess20-34 chased exists because v5's
 * release sites do steps 1-4 inconsistently (some skip step 4, some
 * have escape hatches like skip_locked=1). The chokepoint guarantees
 * uniformity.
 */
int mxfs_clayer_release_token(struct mxfs_clayer_token *t);

#endif /* _MXFS_CLAYER_RELEASE_H */
