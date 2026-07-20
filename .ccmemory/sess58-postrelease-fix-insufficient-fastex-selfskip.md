---
name: sess58-postrelease-fix-insufficient-fastex-selfskip
description: sess58 UPDATE: post_release fix (6657565C) did NOT fix zero_silent_loss. P58-SELFSKIP fired 99× on post_release=FALSE paths (FASTEX/iget) — clobber i…
metadata:
  type: project
---

# sess58 UPDATE — post_release self-skip fix is INSUFFICIENT

Builds on [[sess58-durable-lostupdate-selfskip-blockleaf-dir-rootfix]].

## Result of the fix (build 6657565C, deployed + single-iter storm)
Still FAIL. Critically: `P58-SELFSKIP-STALE-DIR` fired **99×** and `P58-STALE-BASE-ADD`
**26×** AFTER the fix. Since the fix makes `post_release=true` set
`mxfs_dir_disk_superset=true` (which SKIPS the self-skip branch entirely, where the
P58-SELFSKIP probe lives), **every one of those 99 fires is necessarily a
post_release=FALSE call**. So the clobbering self-skip is NOT on the slow-path EX-acquire
(xfs_mxfs_dlm.c:5942, which I set true) — it is on one of the post_release=FALSE callers:
- :5579 FASTEX same-tenure dir_ex_stale_refresh (kept false to avoid sess36 rollback)
- xfs_inode.c:875/1010 iget recycle/cache-miss (kept false)
- xfs_icache.c ×5 (kept false)

## Why the slow-path fix missed
The create-storm hot path is the FASTEX (cached-EX) refresh, not the from-NL slow path.
A node holding cached EX should exclude peers, yet dir_gen>>loaded_gen there means EITHER
(a) phantom dual-EX (mutual-exclusion violation — sess107/sess128 territory) so a peer DID
modify while we "held" EX, OR (b) loaded_gen never advances on the slow path so the gap is
self-inflicted bookkeeping. NOTE: loaded_gen is advanced ONLY in the FASTEX evict block
(~xfs_mxfs_dlm.c:5541, `if gen==want_gen && left==0`); the slow-path reload at :5942 may
NOT advance loaded_gen at all → dir_gen>loaded_gen persists forever → P58-STALE-BASE-ADD
keeps firing even if the base is actually fresh (possible false-positive on the probe).

## NEXT (sess59) — RULE 4
1. Add `post_release` + a caller-site tag to the P58-SELFSKIP-STALE-DIR log so the next
   run shows WHICH caller (fastex vs iget vs icache) keeps the stale base immediately
   before a clobber. That pins the real path.
2. Investigate whether loaded_gen is advanced on the slow-path reload (:5942). If not, the
   gen metric is broken and the whole stale_refresh machinery is keying on stale
   bookkeeping. Consider advancing loaded_gen after a successful slow-path reload.
3. Consider phantom dual-EX: re-check sess128 phantom-EX rearm — is a peer modifying the
   shared dir while this node holds (believes it holds) cached EX? Probe on-disk holder
   (mxfs_v5_dlm_inode_held) at the FASTEX self-skip.

## SEPARATE ISSUE blocking clean measurement
zero_silent_loss iter keeps ending "VERIFY FAILED (node0 find returned non-numeric) —
counting as loss" (=1600). This is node0's verify-phase `find` over /mnt/shared returning
a non-numeric count (likely a traversal EIO/ESTALE into some subdir, or find printing an
error to stdout). It MASKS the true silent count. sess59: make the verify robust (capture
find stderr, retry) OR diagnose why node0's find errors — it may itself be a real bug
(some node-created subdir tree is inaccessible cluster-wide). Check
scripts/sess88_workload_a_modeN_baseline.sh verify phase.

Fix build 6657565C is deployed on test1-16. Probes P58-STALE-BASE-ADD (xfs_dir2.c),
P58-SELFSKIP-STALE-DIR (xfs_mxfs_dlm.c) are always-on rate-limited.
</body>
