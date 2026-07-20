---
name: caw-4node-COMPLETE-PICTURE-two-paths-fb0-vs-fb1
description: TOP PRIORITY: 4/caw reduces to a force_block tension. fb=0: cache_coherency+zero_silent_loss PASS (confirmed x2), dir_reuse SLOW-TIMEOUT (known sess2…
metadata:
  type: project
---

## 4/caw COMPLETE PICTURE — the force_block tension, two paths (sess3, 2026-07-07) — READ FIRST

The 4/caw blocker reduces cleanly to ONE tension. Measured this session (build B6F0D45F, mpatha,
runtime `MXFS_EXTRA_MODARGS="dir_force_block=0"`, NO code change):

| test (4/caw)        | fb=1 (current default)                  | fb=0                                   |
|---------------------|-----------------------------------------|----------------------------------------|
| cache_coherency     | FAIL 0/4 — block-collision CORRUPTION→shutdown | **PASS 4/4 (confirmed x2, 48s clean)** |
| zero_silent_loss    | FAIL 0/4 — same root                     | **PASS 4/4**                            |
| dir_reuse_coherency | **PASS**                                 | FAIL — 300s TIMEOUT (SLOW/stall, NO corruption, nodes stay mounted) |

### Why (root understood)
- fb=1 forces block-format dirs → the shared subdir's single dir block (agbno9/AG) is a hot cross-node
  RMW hotspot → file-data/torn-RMW aliasing → dir3 CRC → SHUTDOWN (this session's deep diagnosis,
  [[caw-4node-cache_coherency-SESSION3-SUMMARY-START-HERE]], [[caw-4node-doublealloc-REFINED-3faces-aglow-probes-and-fix-plan]]).
- fb=0 = natural XFS (shortform dirs live IN the inode) → no shared dir block → coherency pair GENUINELY
  passes. But dir_reuse (24 rounds x 100 files x 4 nodes create/verify/drop_caches/rm-rf) does heavy
  sf<->block conversion churn at fb=0 → too slow / drop_caches-eviction-vs-peer-rm-DLM-release interlock
  (the test's own sess14 guard) → 300s timeout. KNOWN issue: [[sess20-8tcp-16of17-only-dir_reuse-insuite-timeout-speed]]
  (dir_reuse in-suite 300s TIMEOUT is a long-standing SPEED problem, NOT correctness). fb=0 dir_reuse
  did NOT corrupt: Shutting-down=0, no -117/CRC, normal progress (P9 ifree, P56-RELOAD-MERGE).

### TWO PATHS TO THE CRITERIA (pick one, next session)
**Path A (RECOMMENDED — tractable): fb=0 + make dir_reuse fast/coherent enough to pass in budget.**
- fb=0 is the principled config (natural XFS) and already turns 2 RED cells GREEN, confirmed x2.
- Remaining work = the dir_reuse SLOWNESS/stall at fb=0: instrument which barrier/round stalls; is it
  drop_caches eviction interlock (sess14) worsened by sf<->block churn, or slow EX-handoff on the
  reused dir inode across rounds? Speed up the sf<->block conversion cross-node handoff, OR the
  drop_caches-vs-rm-storm interlock. This is a PERF/stall fix (no corruption) — more tractable than
  Path B's corruption.
- THEN validate fb=0 across the WHOLE ladder (1/2/8/16/32 caw) — must not regress other tests before
  flipping the default `int mxfs_dir_force_block=1` (xfs_mxfs_dlm.c:7908) to 0.

**Path B (deep): keep fb=1 + fix the block-format shared-dir-block cross-node coherence corruption.**
- The ~40-session bnobt/dir-block double-alloc swamp. Prime suspects: concurrent-EX via CAW CAS, or
  owner-durability race (see [[caw-4node-cache_coherency-SESSION3-SUMMARY-START-HERE]] for the decisive
  raw-CAW-popcount ledger experiment). Fable consulted once. Harder (corruption, not perf).

### STATE / next
- criteria.json now shows 4/caw cache_coherency=PASS, zero_silent_loss=PASS — but those were recorded
  AT fb=0 (config-dependent). At the DEFAULT fb=1 they FAIL. The criteria needs a config+code combo
  that passes ALL 4/caw tests, then the full 1/2/4/8/16/32 ladder.
- Also still open: 32/caw dlm_scaling perf ([[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]]); untested
  16/caw + many 32/caw cells.
- Build B6F0D45F has light P-AGLOW probes (remove before final). Cluster: 4 nodes mounted (fb=0 last).
- Start next session at Path A: diagnose the dir_reuse fb=0 stall.
</body>
