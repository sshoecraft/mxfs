---
name: sess14run-STATE-r6-drc-wholeblob-and-tds-insuite-drag
description: sess14 mid: r6 15/17 (build 11FAB23A). tds in-suite 66-72s correct-but-slow (drag=op-inflation post-drc-kill); drc = whole-blob block-dir loss (no DI…
metadata:
  type: project
---

# sess14 state after iter r6 (build 11FAB23A = floor + FIX-F + P14 tripwires)

## r6 results (8/tcp, fixed suite_iter 2600s — full 17 ran)
15/17: everything passes EXCEPT drc (0/8, 800s budget kill at ~round 10)
and tds (0/8: 150/150 correct everywhere but 66-100s vs 60 window).

## tds in-suite vs standalone (41.7s PASS standalone, same floor build)
- Release profile UNCHANGED in-suite (dur 11.4ms avg, n=2240) — the drag is
  MORE handoffs (2240 vs ~1300; op-time inflation breaks round batching) +
  slower ops while holding. Common upstream = suite-prefix FS aging AND
  drc's kill aftermath (AIL residue, 800 leftover files, fuser -k).
- gap run (drc first, fresh): drc PASS, fence/netpart/soak PASS, tds FAIL
  by WEDGE (see sess14run-FIXES memory: test4 sf-corrupt AIL wedge 184s).
  That wedge did NOT recur in r6 (P14 tripwires silent, no 240s stalls).

## drc r6 facts (artifact /tmp/run_dir_reuse_coherency_20260704T174930Z)
- Rounds 62s (r4: 24.6s) — NOT build (FIX-F/P14 paths 0 fires in both) —
  the miss-forensics death spiral: 15 fail-round-node events × (6000-line
  dmesg dump + 32 dd blkdumps + classify) inflate rounds, blow 800s.
- Faces: 795/800 ×8 (5-file) and 700/800 ×7 (WHOLE-BLOB: node1's own blob
  + node5's blob in different rounds; 100× LOOKUP_ENOENT REREAD_MISS =
  durably absent).
- DIRID: ALL nodes agree every round (8929024 r2-8, 161 r9+) — NO
  incarnation divergence (fresh files this time; cleanup works). The loss
  is INTRA-INODE block/leaf dir content (sess83-88 stale-base RMW family).
- P91-FUA-SKIP=0, P12-IGETMISS=0 in drc runs — the FIX-D/E/F ladder is
  inert here; different producer.

## Open work, priority order
1. drc whole-blob block-dir loss: mine r6 P50-WR/P50-RD ledger for the
   write that reverted the victim blob (owner/cnt/incarn per dir write,
   already always-on). Then root-fix at the writer (stale-base RMW guard).
2. drc forensic death-spiral: gate the in-round heavy forensics behind
   DRC_FORENSICS env (keep failrounds.txt + RDMISS lines). Halves round
   inflation; NOT a substitute for fixing the face (misses fail rounds
   regardless of pace).
3. tds in-suite margin: after drc green, re-measure; if still >60s,
   options = F2 release-cost cuts (sa/b2/sd redundant flush surgery,
   risky) or sf_mht 15->2x retune.
4. Then 1/2-node columns + repeats.

## Builds
- 5A31CD27 = floor only (tds standalone 41.7s PASS 8/8; gap run mostly ok)
- 360111F2 = + FIX-F (never regression-tested alone)
- 11FAB23A = + P14 tripwires (r6, current NFS). All co-exist safely.

## Watchouts
- iter logs buffer through `| tail -25`: nothing visible until run.sh
  exits. Watch /tmp/run_* artifacts or node dmesg for live progress.
- suite_iter recycles VMs itself; gap-style ./run.sh does NOT (leftover
  wedges after kills → virsh destroy+start test1-8 first).
- tds artifacts only pulled on FAIL; PASS elapsed lives in node dmesg
  (mxfs-TDS lines).
