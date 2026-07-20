---
name: sess66-zsl-bmbt-leaf-xfsaild-clobber-tenure-gate
description: sess66: zsl ROOT DEFINITIVELY PROVEN via P66-LEAFWRITE — xfsaild writes stale bmbt leaf (no EX gate) clobbering peer's shared on-disk leaf; di is EX-…
metadata:
  type: project
---

## sess66 (ccloop 14d31183) — zero_silent_loss ROOT DEFINITIVELY PROVEN + 3 fixes (build 88688A48, BUILT, NOT YET TESTED)

zsl STILL FAILS at session end (marker NOT written), but the root is now nailed with a decisive write-side probe, and a proven-template fix is built. Cluster is dirty (storm-shutdown nodes) — power-cycle (`scripts/cluster_reset_n.sh 16`) before next run.

### THE ROOT (PROVEN, P66-LEAFWRITE probe in xfs_bmbt_write_verify, xfs_bmap_btree.c)
Every bmbt LEAF write for the shared storm dir (owner=131, single leaf daddr=29222600) has **comm=xfsaild/sda**, and DIFFERENT nodes write DIFFERENT (stale) numrecs to the SAME shared daddr (test3 writes 14, test4 writes 16, while a peer grew the dir to 30). The dinode (di_nextents) IS DLM-EX-gated (P119 at xfs_inode.c:4144 + P17B epoch guard in xfs_iflush), so it advances to the latest owner's count (30). The bmbt LEAF buffer has an INDEPENDENT xfsaild/delwri writeback path with **NO EX gate**, so a node that yielded EX (or re-acquired with a lingering prior-tenure leaf BLI) writes its stale leaf over the peer's durable leaf → on-disk **di=N / leaf=N-k torn pair** → a reloading peer trips `ir.loaded != if_nextents` at xfs_bmap.c:1286 (P59-IREAD-MISMATCH loaded=N-k if_nextents=N) → EFSCORRUPTED → FS shutdown → the whole 16-node 1600-dirent cascade (visible=0).

The existing gate `mxfs_buf_xfsaild_skip_bmbt_write` (sess60) only skipped when `i_dlm_mode==NL` — it MISSED the re-acquired-EX-with-lingering-prior-tenure-BLI case (mode=EX, not NL).

### FIXES THIS SESSION (all in build 88688A48)
1. **need_iread guard on the lazy invalidate hook** `mxfs_dir_bmbt_invalidate_stale` (xfs_mxfs_dlm.c ~8010): only invalidate the cached leaf when `xfs_need_iread_extents` (iext NOT loaded). PROVEN GOOD — **eliminated P64-LEFTCONTIG-DESYNC entirely** (the mid-transaction leaf-revert: invalidating while iext loaded reverted the leaf buffer away from the authoritative iext tree → comm=mkdir i!=1 shutdown). Mirrors sess60's evict-call-site guard.
2. **drain-pin-then-evict for pin-ONLY stale leaf** in `mxfs_dir_evict_bmbt_blocks` (acquire/reload path): mirror the sess74/sess97 dir-DATA idiom (one xfs_log_force(SYNC) if any pin-only + bounded 50-iter unpin wait, then clear XBF_DONE). Reduced create-failures but P59 persisted (the dominant producer was write-side, not read-side).
3. **TENURE-AUTHORITY write gate (the root fix)**: mirror the proven AG-meta b_tenure_id mechanism (sess123/sess125). New `mxfs_dir_bmbt_track(bp)` stamps `bp->b_tenure_id = owner_dir->i_mxfs_ex_grant_seq` at MODIFY time (hooked in xfs_trans_log_buf for `bp->b_ops == xfs_bmbt_buf_ops`, multi-node only). `mxfs_buf_xfsaild_skip_bmbt_write` now ALSO skips+stales when `bp->b_tenure_id != ip->i_mxfs_ex_grant_seq` (leaf logged in a PRIOR EX tenure = superseded → don't clobber peer). A leaf modified THIS tenure has stamp==current → writes normally (no data loss). b_tenure_id reuse is safe (bmbt is never AG-meta). bmbt leaf reads do NOT stamp b_mxfs_dir_gen, which is why a gen-based gate would false-skip — the modify-time epoch stamp is the correct discriminator.

### NEXT STEP (was at relay boundary right after a clean build)
`scripts/cluster_reset_n.sh 16` → clear dmesg all nodes → `bash scripts/p133_storm_errcap.sh /src/mxfs/mxfs.ko 100` (foreground/bg, timeout 300). Expect: no early shutdown, visible≈1600, true_silent_loss=0, P59-IREAD-MISMATCH→0. Watch P66-LEAFWRITE (now rate-limited): a stale-count write should no longer land for owner=131 from a non-current-tenure node. If P59 persists, check whether the lingering prior-tenure leaf BLI is being CLOBBERED via a path other than xfsaild push (e.g. the release-drain mxfs_dir_bmbt_scan flushing a stale leaf), and whether i_mxfs_ex_grant_seq is correctly bumped/stamped (add a probe to mxfs_dir_bmbt_track logging owner/stamp and to the skip logging stamp-vs-current). Then run `tests/criteria/zero_silent_loss.sh --iters 3 --dpn 100 --mode 1` (budget 300s) for the criterion.

Other 3 criteria still FAIL (untouched): fence_during_write (lost=400), rsync_paired (148%), posix_semantics_multi16 (>600s timeout).

Links: [[sess65-zsl-dlm-handoff-metadata-coherency-root]] [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]]
