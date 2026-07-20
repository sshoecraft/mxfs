---
name: sess15run-FIXJ-single-node-logforce-and-paired-bench-state
description: sess15 FIX-J2 (0F1666F1): single-node paired gap 17%→~5% — throttled per-128-unlock async log_force was 211 FUA+FLUSH ops/rsync. Bench now balanced-r…
metadata:
  type: project
---

# FIX-J — single_node_paired perf root + honest bench protocol

## ROOT (RULE-4 chain, all measured)
single_node_paired failing 114-144%: mxfs leg ~3.4-3.6s vs native 2.8-2.9s.
1. Geometry EXONERATED: native mkfs.xfs -d agcount=50 -i size=512 (mxfs's
   exact geometry) = 2830ms ≈ native defaults.
2. Diskstats: writes identical; reads 416 vs 405 vs the CORRECT control —
   read-count theory DEAD (native-50AG does the same 7-reads-per-AG walk).
3. blk_rq_issue mix: mxfs 378 standalone FLUSH + 215 WFSM (FUA log writes)
   vs native 27 + 14 → ~550 extra barrier round-trips = the whole gap.
4. ftrace + stacks: 211 of 213 xfs_log_force calls from
   mxfs_ag_dlm_unlock.part.0 — the v0.3.136 THROTTLED async force
   (every-128th unlock, ~27k unlocks/rsync).  NOT the eager quantum drain
   (FIX-J part 1 gated that too, harmless).
5. FIX-J2: gate the throttled force on !is_single_node (CIL pushing single-
   node = native XFS's own job: xlog worker, log-space thresholds, xfsaild
   pinned-item force; the sess31 SOLO wedge this force patched was root-fixed
   by the lazy-path async submit which stays).  Result: 213 forces → 3,
   FF 378→12, WFSM 215→6, leg 3.4s→2.9-3.1s.

## Paired-bench protocol (tests/tooling/single_node_paired.sh, rewritten)
Old single-leg X-then-M was a host-cache coin flip (xfs leg 2681-3377ms
across laps; disk.img backing-file writeback accumulates ~700MB/leg and
strict alternation always gives xfs pole position).  Now: 4 position-balanced
rounds (XM, MX, MX, XM), per-round internal ratio, trimmed mean (drop
best+worst round).  Threshold still 105%.  Legs echo "ms files" (subshell
var loss fixed — the old file-count check compared empty-vs-empty).

## Honest current state
Balanced-round ratios: {99,102,105,107}=103, {82,101,105,105}=103,
{100,105,109,111}=107, {105,107,108,109}=107.  TRUE residual floor ≈ +5%
vs native (I/O counts now match/beat native; native xfs symbols 7.96% of
cycles vs [mxfs] DSO 9.93% ≈ +2% wall; rest = IO-wait shape).  Verdicts
will flip-flop at the 105 bar until another ~3-5% is found.  Candidate next
steps: per-symbol diff with resolved module symbols (perf report must run
with module still loaded), deferred-unlock kmalloc-per-trans inline for
single-node, journal-slice mount log size vs native (256MB/4=64MB — check
actual l_logsize), disklock heartbeat interplay.

## Builds
0F1666F1 = 61FE57FD (FIX-H3+P15I+FIX-I) + FIX-J1+J2.  Multi-node semantics
untouched by J (both gates are is_single_node-only; peer-join catch-up =
the BAST drain, unchanged).
