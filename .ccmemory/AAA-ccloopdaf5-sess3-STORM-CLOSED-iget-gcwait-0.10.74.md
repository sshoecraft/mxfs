---
name: AAA-ccloopdaf5-sess3-STORM-CLOSED-iget-gcwait-0.10.74
description: sess3: mkdir_storm CLOSED — 30/30 NO HIT on 0.10.74 84FCBF6F. Root: iget-vs-inodegc ENOENT on reused ino (gcwait fix). Claim guard validated. Ladder…
metadata:
  type: project
tags: [ccloop-daf50d34, storm, iget-gcwait, 0.10.74]
---

# sess3: storm family CLOSED on 0.10.74 (srcversion 84FCBF6FF9F30138E2B5836)

## Round-3 HIT root (RULE-4 chain complete, all evidence in storm6 harvest)
`mkdir_storm` r3 "node1 missing": test1's path walk of the freshly-recreated `.mkdir_storm`
(ino 10487891, created cross-node by N20-23) found the dirent but **iget failed ENOENT ×2**
(`P26-IGET-FAIL dp=128 inum=10487891 err=-2` at 1037.916 + 1038.324; 16× P13-GCFLUSH):
a prior-incarnation shell of the REUSED ino was mid-teardown (I_FREEING, igrab fails) behind an
~18-inode inodegc backlog (test1's rm -rf of the previous round's dir + its DLM teardowns).
The lookup's 8-try/~360ms budget expired; shell cleared ~5s later. `mkdir $P/node1` died
ENOENT in path resolution (storm script masks rc) → dirent never created anywhere → honest
31/32 verify = HIT.

## Fix (0.10.74)
- `mxfs_dlm_iget_shell_reload` returns **2** for the mid-teardown/GCFLUSH case (guaranteed-progress wait).
- `xfs_lookup` retry loop: `acted==2` gets its own budget `gcwait_tries<400` × msleep(20) ≈ 8s max,
  not counted against the 8-try nudge budget. No locks held across the sleep (only VFS i_rwsem shared).
- Storm7 = **30/30 NO HIT** (previously HIT ≤ r5 on every build). GCFLUSH=0 IGET-FAIL=0 this run
  (timing didn't recreate the race, but nothing gave up); FOREIGN-STRIP=0; P-CLAIM-RACE-LOST=22
  (0.10.73 claim guard actively working).

## Disproven / non-bugs (do NOT re-chase)
- "Stale readdir in rm": DISPROVEN — rm's getdents read fresh cnt=34 (`P50-RD comm=rm`).
- "rmdir non-empty orphaned 14 subdirs": NON-BUG — rm unlinked all 32 locally (removals 19-32
  batched in one MHT tenure; block updates legitimately discarded when rmdir+ifree freed the dir
  block). Children ifreed via their own inode-cluster destages. Freed block retains stale dirent
  image = free-space garbage (ABA machinery already handles reuse: P-DBLALLOC-BIRTH foreign=1).
- Round-2 "paradoxes" earlier in session = round mis-mapping (waves: r1=52955217, r2=69206144,
  r3=10487891 — `.mkdir_storm` recreated per round, inos cycle/reuse).

## Residuals (watch, not blockers)
- TENURE-REFUSE=211 cluster-wide in storm7 with ZERO loss (release-path destage refusals; data
  lands via next-acquire merge or dying-dir discard). Design debt: refuse assumes "next acquire
  merges" — void for delete-then-free, but that case discards legitimately.
- **dlm_scaling@32 rate marginality**: r79 (0.10.74 deploy) FAILED 31/32 `ds node27 rate>=floor`
  (floor 50/s; aggregate 1833, avg 57, max 59). node27 had ONE 2377ms EX P138-WAIT (ino=10485888,
  parent dir) — the ACQ-WAIT 2s stall family (playbook: caw_epoch_free_reset stale-slot-inheritance
  designed-never-implemented). GCFLUSH=0 on node27 → NOT caused by the gcwait fix. r78 (0.10.73)
  passed 32/32. If it recurs: dedicated RULE-4 loop with instr=1 during the run.

## NEXT (criteria ladder on 0.10.74, matrix_check.py --since <epoch-of-first-0.10.74-pass> = YES gate)
1. dlm_scaling@32 clean PASS needed on 0.10.74 (rerun `revalidate_cell.sh 32 t:dlm_scaling` or full g1).
2. g2@32 (`revalidate_cell.sh 32 g2`), dir_reuse@32 (`32 dr`).
3. 16 nodes (nodr+dr), then 8/4/2/1 full.
4. `scripts/matrix_check.py --since ...` all-green → echo YES > /src/mxfs/.ccloop/runs/daf50d34-cc16-4192-9dda-6e2589c78764/criteria-met
- Storm harvest: $SP/storm6/ (45MB, 32 nodes) + blk0.bin (orphan dir block dump) in sess3 scratchpad
  /tmp/claude-1000/-src-mxfs/5aba6f97-2f3f-488d-ae26-a5dc0e30acaa/scratchpad.
- Cluster: 32 nodes on 0.10.74, instr=1 dirwr=1 LIVE (rings full of P135 traffic — disable before perf runs!).
