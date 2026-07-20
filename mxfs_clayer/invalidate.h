/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mxfs_clayer/invalidate.h — v6a invalidation primitives (sess35 sketch)
 *
 * STATUS: SKETCH ONLY. Not wired into anything yet. Sess36+ task is to
 * implement these and integrate them at the bast_process / ilock_begin
 * chokepoints, replacing v5's bolted-on per-callsite invalidations.
 *
 * Per `docs/v6-cache-architecture-proposal.md` §3.2 — five GFS2-shaped
 * primitives, all kernel-internal:
 *
 *   mxfs_invalidate_ag(ag_no)         — drop AG metadata buf cache
 *   mxfs_invalidate_inode(ino)        — drop inode struct + dir bufs
 *   mxfs_pagecache_inval_inode(ino)   — drop file pages
 *   mxfs_ail_push_ag_sync(ag_no)      — per-AG AIL drain (already implemented)
 *   mxfs_log_force_resource(R)        — per-resource log force (deferred to v6b)
 *
 * Sess35 evidence: Mode A duplicate-create persists in v5 because v5's
 * bolted-on invalidation in BAST-DIR-STALE walk has a `skip_locked=1`
 * escape hatch (bp->b_addr modified in memory, peer reads disk before
 * iflush completes). The chokepoint architecture eliminates the escape
 * by serializing the WHOLE drain+invalidate before unlock, with no
 * code path that can release the DLM lock without going through it.
 */
#ifndef _MXFS_CLAYER_INVALIDATE_H
#define _MXFS_CLAYER_INVALIDATE_H

#include <linux/types.h>

struct xfs_mount;
struct xfs_inode;
struct xfs_perag;

/*
 * mxfs_invalidate_ag — drop ALL cached AG metadata buffers for `ag_no`.
 *
 * Called from the chokepoint mxfs_clayer_release_token() AFTER per-AG
 * AIL drain + log force + blkdev_flush completes, BEFORE the DLM
 * unlock message is sent. Also called from mxfs_clayer_acquire_token()
 * after a peer-modified grant before allowing reads.
 *
 * Walks the AG's metadata block list (AGF + AGI + AGFL + bnobt/cntbt/
 * inobt/finobt/rmapbt/refcountbt root + transitive btree blocks +
 * inode chunks) and calls xfs_buf_stale + xfs_buf_relse on each.
 *
 * Returns 0 on success or -errno on failure.
 *
 * Implementation note: the existing v5 code at
 * xfs/xfs_mxfs_dlm.c:2480-2716 (sess25 v0.3.84/.99/.105) walks
 * pag_bcache.bc_hash via rhashtable. v6a should consolidate that
 * into this primitive and remove the per-callsite scatter.
 */
int mxfs_invalidate_ag(struct xfs_mount *mp, xfs_agnumber_t ag_no);

/*
 * mxfs_invalidate_inode — drop in-core inode + dir block bufs for `ino`.
 *
 * For directory inodes: walks the dir's extent map, calls xfs_buf_stale +
 * relse on each cached dir3 buf. For file inodes: invalidates the data
 * mapping if PCACHE-class token is being released.
 *
 * Called from chokepoint mxfs_clayer_release_token() for inode-token
 * release. Sets ip->i_dlm_stale = true; mxfs_dlm_ilock_begin will
 * reload from disk on the next acquire.
 *
 * Mode A specific: this REPLACES the BAST-DIR-STALE walk in
 * xfs/xfs_mxfs_dlm.c::mxfs_dlm_bast_process line 403-477. Crucially,
 * it does NOT use trylock; instead it forces xfsaild to push the dir
 * buf via xfs_buf_delwri_pushbuf or equivalent, then waits for
 * completion. No skip_locked escape.
 *
 * Returns 0 on success or -errno on failure.
 */
int mxfs_invalidate_inode(struct xfs_inode *ip);

/*
 * mxfs_pagecache_inval_inode — drop file pages for `ip`.
 *
 * Wraps truncate_inode_pages_final(VFS_I(ip)->i_mapping, 0). Called
 * when a PCACHE-class token is being released to a peer.
 *
 * For v6a phase 1, single-class-per-inode tokens; PCACHE is implicit
 * with EX/PR. v6 multi-class tokens (D3) is a separate feature.
 */
int mxfs_pagecache_inval_inode(struct xfs_inode *ip);

#endif /* _MXFS_CLAYER_INVALIDATE_H */
