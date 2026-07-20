---
name: sess15-FIX-DESIGN-buffer-incarnation-stamp
description: sess15 CONCRETE FIX DESIGN for crash_consistency 2/tcp: buffer-level incarnation stamp (b_mxfs_dir_incarn) to invalidate previous-incarnation in-AIL…
metadata:
  type: project
---

## sess15 CONCRETE FIX DESIGN (implement next; reasoned from the proven DIR-STALE-SKIP root in [[sess15-HEAD-status]]).

## THE PROBLEM (precise): crash_consistency 2/tcp loses dirents because a node reads/RMWs a dir DATA block whose cached buffer holds a PREVIOUS INCARNATION's content of a REUSED inode number. Signature: `DIR-STALE-SKIP buf_gen=0 in_ail=1 dirty=0 li_empty=1` — the buffer is in-AIL + "undestaged" (b_mxfs_logged_seq != b_mxfs_written_seq from the OLD incarnation), so both the read-path invalidation hook (xfs_da_read_buf ~3184) AND mxfs_dir_evict_data_blocks SKIP it (undestaged guard, sess43/sess133). It is the SAME inode NUMBER reused (P15-ABA owner check fired 0× — dir3 block header owner = inode number = matches), so the owner check and dir-gen check can't distinguish incarnations.

## WHY simple fixes are UNSAFE: buf_gen=0 / in-AIL / undestaged can ALSO describe a CURRENT freshly-allocated-and-initialized dir block (xfs_dir3_data_init does xfs_trans_get_buf, never the read-stamp, so buf_gen stays 0; then it's logged → in-AIL undestaged). Blanket-invalidating buf_gen=0 or undestaged-in-AIL would corrupt/lose the current incarnation's just-created block. force_evict (clean-only) and the owner check both proven insufficient this session.

## THE DISCRIMINATOR = inode i_generation (XFS bumps di_gen on every inode realloc). The previous-incarnation buffer was stamped under the OLD i_generation; the current incarnation has a NEW i_generation. The block header carries NO generation, so add it at the BUFFER level:

## DESIGN (buffer-level incarnation stamp, mirrors the existing inode-level i_dlm_dir_evicted_incarn sess104 machinery):
1. Add `uint32_t b_mxfs_dir_incarn;` to struct xfs_buf (xfs/xfs_buf.h or pal buf struct — find where b_mxfs_dir_gen lives, add beside it).
2. STAMP it = VFS_I(dp)->i_generation whenever a dir DATA/BLOCK block is legitimately read or initialized FOR a specific dir inode: (a) xfs_da_read_buf success path (the dir_stamp_fresh site, alongside b_mxfs_dir_gen stamping ~xfs_da_btree.c:3079-3091); (b) xfs_dir3_data_init / xfs_dir3_block_init (after init, stamp current i_generation); (c) the post-read stamp in the hook. Only for S_ISDIR + DATA fork.
3. COMPARE on read-path cache-hit (xfs_da_read_buf hook ~3055): if `cbp->b_mxfs_dir_incarn != VFS_I(dp)->i_generation` → the cached buffer is a DIFFERENT incarnation = ABA stale → INVALIDATE (clear XBF_DONE|_XBF_FUA_FRESH) and re-read, **BYPASSING the dirty/in-AIL/undestaged guard** — because a different-incarnation buffer's in-AIL "undestaged" content belongs to the FREED previous incarnation (its home-write was cancelled by binval on free; logged_seq/written_seq are stale bookkeeping), so discarding it loses nothing of the CURRENT incarnation. (Safety: the current incarnation's OWN buffers carry the current i_generation → never invalidated.)
4. ALSO add the same incarn-bypass to mxfs_dir_evict_data_blocks (modify/consumer refresh path, xfs_mxfs_dlm.c ~1849): when the buffer's b_mxfs_dir_incarn != current i_generation, stale it regardless of dirty/in-AIL. This covers the owned_ex modify (create RMW) path where the read-hook is gated off by !owned_ex.
5. Initialize b_mxfs_dir_incarn=0 on buffer alloc; 0 != any real i_generation so a never-stamped buffer is treated as needing a fresh read (safe).

## VALIDATE: build, deploy both nodes, `tests/cc_blockdir_probe.sh 30 50` must be 0-loss; then FULL `./run.sh 2 tcp` — crash_consistency must PASS in-suite (run 3× for the flake). Watch for NO regression in the other 15 (esp. dlm_fairness/rsync perf — the incarn compare is cheap, no FUA). Detectors P15-ABA / DIR-STALE-SKIP (dirwr=1) confirm engagement: DIR-STALE-SKIP count should drop to ~0 and a new invalidate should fire instead.

## NOTE: also consider the cross-node free-invalidation gap (the ROOT enabler): a peer that CACHED a daddr during an earlier test never invalidates it when ANOTHER node frees+reallocs it (eviction-ring lossy on TCP). The buffer-incarn stamp fixes the SYMPTOM at read/RMW time reliably (per-inode i_generation is authoritative on-disk and reloaded), which is the cheaper, sound path vs making the eviction-ring reliable. [[sess15-HEAD-status]] [[sess15-PIVOTAL-loss-requires-inode-daddr-reuse]] [[sess15-crash-consistency-is-sole-blocker-divergent-block]]
