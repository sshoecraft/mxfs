---
name: ccloop-c7ee71c6-sess14-C-D2-ab-proven-barrier-dual-role-and-D3-arm3-epoch-fence
description: sess14: D2 A/B — barrier IS the 7.6× slope AND load-bearing (off ⇒ ds got=0 stalls); D3 arm-3 P32E epoch fence deployed after fdw ghost n5_8; v0.11.1…
metadata:
  type: project
tags: [d2, d3, ab-test, barrier, epoch-fence, ghost-dirent, 32-node, open]
---

# sess14-C: D2 barrier A/B + D3 arm-3 (fdw ghost) — v0.11.121/.122

## D3 second variant captured and fenced (fdw ghost dirent, 17:03, v0.11.120)
fence_during_write FAIL: "shared hot dir drained exp=0 got=1" — ghost `n5_8` in SF hot dir
(dp=56623240, cluster daddr=56517176): dirent present cluster-wide, `stat` ENOENT
(P26-IGET-FAIL inum=31457442 err=-2). Wall-merged P56-DIRWRITE/P13-SFRM ledger
(tests/logs/d3ring_20260726_170627_fdw + realns-offset alignment):
- 17:03:40.870 test5 (EX): P13-SFRM removes n5_8; .871 writes post-remove fork
  [n17_6 n26_12 n4_9] — the removal LANDED on the platter.
- **17:03:41.037 test8 `mode=0` writes [.. n5_8] (pre-remove image); 41.141 test24 same** —
  xfsaild flushing RETAINED zombie dir items at NL after release; resurrection durable.
- Every later EX tenure re-adopts n5_8 from disk; final write=[n5_8] alone = ghost born.
FIX arm 3 (v0.11.121): **P32E-DIREPOCH-FENCE** in xfs_iflush — same-incarnation dir whose
master dir_epoch > i_dlm_dir_valid_epoch (a peer held EX since our copy was valid) →
skip flush + ISTALE_CAW (stale_src=25), param dir_epoch_flush_fence default ON.
(The sess16 dir_nxshrink_fence default-0 note doesn't apply: those events ran under EX
where cur==valid; this class is the post-release NL zombie where the predicate is exact.)
First live interception: test19 ino 60817544 fmt=1 valid=0 cur=6 mode=0 kworker.
P146D/P32D (arm 1/2 dead-incarnation guards, sess14-B) not yet exercised — trigger needs
the drain-races-reload interleave (~1/12 laps). RELOAD-TYPEFLIP-DIRENT-OK fires ~65/2 laps
(marker set+cleared routinely, no false guard fires).

## D2 A/B (v0.11.122 runtime lever mxfs.dirop_sync_barrier, default 1)
- Barrier ON: fresh dir 0.36 ms/op (2770 ops/s) → after ONE peer ls: 2.74 ms/op
  (365 ops/s) — permanent 7.6× (mechanism confirmed live).
- Barrier OFF (all 32): aged dir 0.50-0.54 ms/op — slope GONE…
- …BUT storm+chain with OFF: dlm_scaling FAIL 4 nodes with **completed quota got=0**
  (hard stalls — peers spin on unlanded dirent visibility), drc SLOWER (6 rounds vs 7-8).
  ⇒ barrier is ALSO load-bearing for cross-node progress under contention. Naive removal
  REFUTED. Fix direction: cheapen (drop device-read+FUA verify half?) or coalesce with
  BOUNDED-latency destage (visibility retries must converge in ms). Design pending.
- Also learned: drc's pace slope is NOT primarily the barrier (removal made it worse) —
  suspects: D5 reload-BAIL episodes + visibility waits. drc rounds_done>=8 fails at
  106-110s (7, then 6 rounds) — recurring RULE-0 row FAIL to re-green.
- BARRIER RESTORED to 1 on all 32 after the A/B.

## Cluster/build state at save
v0.11.122 srcver A41156D40102EB8EB6AEBA6 deployed+prepped 32/caw, dirwr=0, barrier=1.
Laps at .121/.122: cc PASS ×3, fdw PASS ×2 (after the .120 ghost), drc pace-FAIL ×3
(6-7/8 rounds), ds FAIL once (barrier-off experiment only). D1 guard P67-NOWAIT-SKIP
417+ hits pre-.120 → keeps firing; no wedges, no NO_TERMINAL_RECORD since the fix.
