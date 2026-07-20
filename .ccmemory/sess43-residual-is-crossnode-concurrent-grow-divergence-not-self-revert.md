---
name: sess43-residual-is-crossnode-concurrent-grow-divergence-not-self-revert
description: sess43: P43/P43B fix the SELF-revert (run#1 PASS) but residual is CROSS-NODE concurrent-grow divergence: both nodes convert/RMW the same fresh incarn…
metadata:
  type: project
---

## sess43 — the dir_reuse 2/tcp residual is CROSS-NODE concurrent-grow divergence (P43/P43B only fix the self-revert)

### Two sub-mechanisms, distinguished this session (RULE 4, build 226E02D6 = P43+P43B):
- **SELF-revert** (run #1 PASS): node1 converts, a reload reverts its in-core block→shortform, node1 re-converts → block0 re-init zeroes its own dirents. FIXED by P43 (early dip) + P43B (post-spin snapshot) guards in mxfs_dlm_reload_inode. Proven: run#1 P43=1+P43B=1 same incarnation → drc-FAIL=0.
- **CROSS-NODE** (run #2 FAIL, the RESIDUAL): BOTH nodes convert/RMW the SAME fresh incarnation independently. Proven via i_gen=3091469659: test2 P42-SFCONV node2_f12 @32711.22; test1 P42-SFCONV node1_f12 @32726.87 (15s later). test1's P43 fired AFTER its conversion (too late). Two block0s (test1 fsb15/daddr120; test2 fsb14) → logical-block0 SPLIT → cold verify orphans one → readdir shortfall + leaf-hash holes.

### WHY test1 diverges (decisive): just before test1's conversion @32726.8, the log shows `P128-REARM-UNPUB ino=131 cache-hit CREATE on reused inode` — test1's create is a CACHE-HIT on its own STALE in-core shortform; it does NOT reload test2's durable BLOCK dir (test2 converted+filled 15s earlier, long durable). The slow-path acquire reload (which would adopt test2's block) did not fire / read stale. So test1 grows its own empty/shortform base and converts → divergent block0.

### Dir structure: test (suite/dir_reuse_coherency.sh) rank1 mkdir + sync + barrier, THEN both nodes add 50 files concurrently to the EMPTY fresh dir. So both legitimately start from empty and grow independently; the per-modify handoff fails to MERGE/reload → divergence. NOT a stale-read of pre-existing files; a fresh-dir concurrent-grow.

### PRIOR ART (do NOT repeat): [[sess18-CORRECTION-transition-redherring-sameblock-rmw-is-root]] — `mxfs_dir_force_block=1` (force new dirs block at mkdir) was TRIED, does NOT help: makes dir block-EMPTY, both nodes still hammer the SAME block0 → lost update (worse, iter2). force_block code in-tree, default 0, leave OFF. [[sess19-dinode-reverts-to-stale-shortform-confirmed]] matches the P62-RELOAD-FORK-SHRINK revert.

### EXISTING machinery to evaluate as the real fix (sess13/sess18):
- `mxfs_dlm_dir_modify_reload_prelock(dp)` (xfs_inode.c:1360, sess13): adopt peer-stale shortform base BEFORE dp ILOCK on create. Investigate why it doesn't reload test1 to test2's block.
- `mxfs_dir_merge_enabled` / `mxfs_dir_merge_peer_into_tp` (sess18 inverse-merge: snapshot-ours/evict/replay peer's fresh image into the create tp). Check if enabled + working.
- The principled fix (GFS2/OCFS2 model): on dir-modify after a BAST, RELOAD the peer's durable dir image before RMW so both nodes converge on ONE block0. The cache-hit path must force a coherent reload.

### NEXT: read mxfs_dlm_dir_modify_reload_prelock + mxfs_dir_merge_peer_into_tp; determine why test1 cache-hits stale instead of reloading test2's block; fix the dir-modify reload coherency (or enable/repair the merge). KEEP P43/P43B (they fix the self-revert sub-case). Verify: drc_cap2 ≥3 runs, ZERO (ino,i_gen) doubles, drc-FAIL=0. [[sess43-PASS-dir-reuse-fixed-P43-P43B-fmtrevert-guards]] [[sess43-two-reload-sites-revert-block-to-shortform-P43-P43B]]
</body>
