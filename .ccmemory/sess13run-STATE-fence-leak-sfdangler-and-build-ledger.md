---
name: sess13run-STATE-fence-leak-sfdangler-and-build-ledger
description: sess13 state: fence n4_14 leak = sf dangling dirent (rm reverted by clean-adopt; ifree destaged). Build ledger + iter census + next probes P13-SFRM/P…
metadata:
  type: project
---

# sess13 mid-state — build ledger, iter census, fence-leak autopsy

## Build ledger (this session)
- 705FDC6E = FIX-C (entry-locks-before-AG-grants, remove+rename).
- 61EFACE7 = +P13-PLACE placement ledger, P64 present2 (node2_f1 tracer).
- B008722F = +FIX-D v1 (iget visibility nudge, raw-DLM PR — insufficient).
- 9F1CC83B = +FIX-D v2 (mxfs_dlm_iget_shell_reload: radix-find dead shell,
  igrab, mxfs_dlm_reload_inode via normal grant+mirror path; ordered
  shell_reload → miss_reload → nudge in xfs_lookup retry ×8).
- E0C0D2C5 = +P13-SFRM (sf removal ledger, watch-gated, in
  xfs_dir2_sf_removename via raw mxfs_watch_ino compare — mxfs_ino_watched
  is a static inline not visible in libxfs sf.c) + P56-RELOAD-MERGE now
  prints ours_cnt/ours=[names] (pre-reload fork view).

## Iter census 4/tcp (17-test suite per iter)
- 705FDC6E: ~11 runs — drc FAIL ×2 (readdir 394/397 vs 400, lookup_fail=0),
  ds got=0 ×2, fairness EUCLEAN ×1, fence family 0.
- 61EFACE7: 3 runs — ds ×1 (075050Z, the FIX-D root evidence).
- B008722F: 1 run — ds ×1 (081037Z: nudge fired ×37 rc=0, no converge →
  led to v2; platter HAD winner dir 0x41ed, cached buf mode=0 delwri 0x80020,
  dead shell incore_mode=0).
- 9F1CC83B: 6 runs — 5 clean + fence_during_write leak ×1 (091132Z).

## fence n4_14 leak autopsy (091132Z + live-cluster query)
- Leftover n4_14 durable on all 4 nodes; hot dir ino=160 SHORTFORM (fmt=1).
- test4 (creator): P26-IGET-FAIL name=n4_14 inum=6295916 err=-2 +
  P127-EEXIST-LOSER → the dirent DANGLES (name on disk sf fork, ino freed
  on disk) → rm can't remove (lookup→iget ENOENT) → permanent leak.
- Mechanism: the rm of n4_14 committed sf-removal + ifree; ifree destaged;
  the DIR-160 dinode (sf minus n4_14) never destaged; later reloads
  clean-adopt disk (P56 merged=0 clean=1 disk=[n4_14]) everywhere →
  removal gone. sf release has a CLEAN-SKIP fast path (P51-REL sf=1
  clean_skip=1 via mxfs_dir_pr_release_fast) — suspect: skips the sf-dinode
  publish for a committed-but-checkpoint-pending removal. NO P4X ledger
  (dirwr off) and NO P13-PLACE (sf adds don't hit data_log_entry) — that's
  why P13-SFRM was added.
- Same family as drc f1 loss (block variant): committed dir-state lost to
  disk-adopt; drc probes (P13-PLACE/P64 present2) armed for next block hit.

## Next
1. Loop `timeout 1100 bash tests/suite_iter.sh 4 tcp` on E0C0D2C5; on fence
   leak → P13-SFRM realns for the victim rm + P51-REL clean_skip at that
   moment + P56 ours vs post; on drc → P13-PLACE/P64 sequence.
2. Root-fix candidates once proven: (a) sf clean-skip release must verify
   the sf dinode is DESTAGED (not just xfs_inode_clean) before skipping the
   publish — cf. p_clean_release definition near P51-REL (xfs_mxfs_dlm.c
   ~11619); (b) adopt-side: clean-adopt must not restore entries the local
   log already removed (needs release-side publish, (a) is the real fix).
3. After 4/tcp stable ×8-10: run 8/tcp, 2/tcp, 1/tcp same build.
