---
name: AAA-sess8-cachecoh32-ROOTS-reload-identical-landed-neg-lookup-dscan-next
description: sess8 FINAL: cache_coherency@32 root = block-dir layout-divergence ping-pong (no 3-way merge for block dirs). reload_skip_identical + dir_ex_verify_c…
metadata:
  type: project
---

# sess8 (ccloop 12e0d157, session 33136bc8) — cache_coherency@32 — FINAL HANDOFF

## SCOREBOARD (unchanged)
1/2/4/8 caw 17/17; 16 caw 16/17 (dir_reuse PENDING); 32 caw 13/17 (cache_coherency FAIL,
crash_consistency FAIL, dlm_scaling PENDING, dir_reuse PENDING).

## BUILD **944B0EAB292DFC5433AC12A** (deployed all 32, cluster healthy+converged at session end)
= 96C5CF1F + TWO landed param-gated fixes (both default ON, keep both):
1. `reload_skip_identical` — mxfs_dlm_reload_inode skips fork destroy/preevict/from_disk when disk dinode
   provably identical (di_changecount==inode_peek_iversion && di_gen && mode/fmt/nx/size). Kills the
   identical-adopt EX loop (proven: was ~630ms/cycle EX rotation on read-only verify). Fired 11985×/run.
2. `dir_ex_verify_caw` — the sess-tcp un-throttled dir-EX held-verify now also on CAW (one 512B slot read
   per pin-free dir-EX cache-hit). Closes the documented P106 phantom-EX window. NOTE: fired only 1×/run —
   phantom-EX is REFUTED as the tear source, but the check is nearly free; keep.

## PROVEN THIS SESSION (RULE 4 chain, all measured)
- Test dies in rename_visibility: cv+cwr <11s, rv_create 16-25s, rv_rename 43-105s, rv_verify NEVER (>185s
  left of 300s budget). Confirmed IDENTICAL phase profile across 3 runs (barrier-watch tool).
- Verify slowness mechanics: dir PR bounces continuously (P-NONE-HELD-IDLE-RELEASE per idle BAST honor);
  each dir op pays release(37-52ms drain)+reacquire; first-op-of-iteration absorbs ~570ms.
- Driver of the churn: **dir LAYOUT DIVERGENCE ping-pong** — in-core data-fork layout ≠ disk at SAME di_gen
  (test1: incore nx=47/212992 vs disk nx=39/221184; P33-FROMDISK-DIRSHRINK; P60-RELAUDIT leafsum=47 vs
  di_nextents=39 INCONSISTENT-AT-RELEASE). Both layouts keep re-publishing (alternating adopts), every
  reload is a REAL adopt → forks keep unloading on affected nodes → iread-EXes → PR bounce storm.
- Tear PRE-EXISTS all sess8 changes (old build run: 102/275 markers; fix3 fresh run: 94/115).
- Phantom-EX (P-TCPEX-REACQ) fired 1× → NOT the divergence source.
- Atime refuted (SB_NOATIME unconditional). Target saturation refuted (nvme 22% util, 0.15ms).
- **LEADING HYPOTHESIS for tear formation (next session's step 1)**: block-format dirs have NO 3-way merge
  (mxfs_dir_sf_merge_into is SHORTFORM-only). A node with committed-not-yet-destaged rename mods self-skips
  the adopt (sess36 guard — must, to not lose its own delta), keeps its whole in-core LAYOUT, then its
  release republishes that layout WHOLESALE — clobbering the peer's layout merged on disk. Last-writer-wins
  at layout level ⇒ divergence is structural under concurrent block-dir grow/shrink (640 renames, 32 nodes).
  The rv workload renames in-place (same dir, same sizes) — layouts diverge via freeindex/leaf block
  grow/shrink races (xfs_dir2_shrink_inode). At ≤16 nodes MHT batching + fewer racers mask it.

## NEXT SESSION PLAN
1. Instrument tear FORMATION: on the rename phase (replay `scripts/diag_rv_replay.sh 32 create|rename hotX`),
   watch INCONSISTENT-AT-RELEASE first appearance + which node kept which layout (P62 incore/disk fields,
   P91-RELOAD-PROTECT / sess36 self-skip firings). Confirm the keep-stale→republish mechanism.
2. Fix directions to evaluate (pick with evidence, RULE 4):
   a. Release-side reconcile: at INCONSISTENT-AT-RELEASE detection (release audit), force re-iread of the
      map from the JUST-DRAINED disk state before unlock (the drain published our mods; disk is now
      canonical superset; re-adopting map post-drain cannot lose our delta).
   b. Adopt-side: for block dirs with dirty self, adopt disk map but RE-APPLY own extent delta?? (hard —
      no merge machinery; likely wrong direction).
   c. Prevent divergence birth: make dir grow/shrink (xfs_dir2_grow_inode/shrink_inode) always run under a
      VERIFIED on-disk EX + fresh map (they may already; check the self-skip path interaction).
3. After tears ≈0: cache_coherency@32 should converge (identical-skip handles quiescence; PR stays cached).
   Then crash_consistency@32, dlm_scaling@32 (validate as-is), dir_reuse@16/32, full ladder.
4. Perf cleanups AFTER correctness: datascan-on-every-miss gating (xfs_dir2_leaf.c:1790); stranded-grant GC
   (P15-REL-ABORT orph=1 28ms loop; holder held dir EX 469s → peer -110 → SHUTDOWN cascade — seen twice
   under long replay grinds; REAL bug, keep on list).

## TOOLS (in tree) + GOTCHAS
- scripts/coord_bar_watch.sh; scripts/diag_rv_replay.sh (per-subop + A/B + node-local logs); diag_rv_verify_ab.sh.
- Fresh prep resets everything: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1"
  ./run.sh 32 caw precond_readiness` (~3min healthy; power-cycles shutdown-poisoned nodes automatically,
  +10min). Wrapper timeout ≥ 950s when nodes may need power-cycling; run.sh enforces the 300s test budget.
- caw_slot_dump.py buffered reads = stale page cache (artifact). kernlogs span boots — time-window always.
- Replay ssh caps kill client only → pkill '.rv_replay' leftovers or they poison the substrate for minutes.
- P138-WAIT logs REQUESTED mode (3=PR 5=EX); P70-BP held_ms = tenure age; MHT 300ms block-dirs (do NOT lower).
