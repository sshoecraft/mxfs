---
name: caw-4node-BREAKTHROUGH-forceblock0-passes-coherency-dirreuse-stalls
description: BREAKTHROUGH (sess3): dir_force_block=0 makes 4/caw cache_coherency AND zero_silent_loss PASS 4/4 (shortform dirs = no shared block collision). dir_r…
metadata:
  type: project
---

## BREAKTHROUGH — dir_force_block A/B decisively separates the two dir-coherence bugs (sess3, 2026-07-07)

Runtime A/B via `MXFS_EXTRA_MODARGS="dir_force_block=0"` (NO code change; build B6F0D45F, mpatha):

| test (4/caw)        | fb=1 (current default) | fb=0 |
|---------------------|------------------------|------|
| cache_coherency     | **FAIL 0/4** (shared block-fmt dir block collision → dir3 CRC → SHUTDOWN) | **PASS 4/4** ✅ |
| zero_silent_loss    | **FAIL 0/4** (same root)          | **PASS 4/4** ✅ |
| dir_reuse_coherency | PASS                              | **STALL/timeout** (300s) — but NO corruption |

### Why this is decisive
- fb=1 forces dirs to BLOCK format immediately → the shared subdir's single dir block (agbno9/AG) is
  a hot cross-node RMW hotspot → the double-alloc/CRC SHUTDOWN family (this whole session's diagnosis:
  [[caw-4node-cache_coherency-SESSION3-SUMMARY-START-HERE]]). fb=1 was a sess67 WORKAROUND for the
  sf→block conversion race (dir_reuse) — it TRADED that race for the block-collision corruption.
- fb=0 = NATURAL XFS (dirs stay shortform in-inode until they grow) → NO shared dir block → the
  coherency pair GENUINELY passes (real coherency, shortform is in the inode, not masked).
- fb=0 dir_reuse FAILURE MODE (measured): all 4 nodes stay MOUNTED, `Shutting down filesystem`=0,
  no error-74/CRC/-117 in tail, nodes show normal progress (P9 ifree DONE, P56-RELOAD-MERGE). So it's
  a **barrier STALL / slowness, NOT a corruption shutdown**. sess4 saw `xfs_dir_create_child -117 /
  xfs_ifree -117` (sf→block race) at fb=0 — may be improved by the ~30 dir_* fixes since; now it
  stalls rather than errors.

### STRATEGIC DIRECTION (reframed)
Pursue **fb=0 + fix the dir_reuse STALL** (tractable — a stall/slowness, no data corruption) rather
than fb=1 + fix the deep cross-node block-collision CORRUPTION (~40-session swamp). fb=0 is the
principled config (natural XFS). Steps for next session:
1. Diagnose the dir_reuse fb=0 stall: which node/barrier stalls, is it the sf→block conversion
   coordination (a peer's sf→block transition not seen → lookup/create stalls waiting on a DLM
   grant / barrier), or EX-handoff slowness on the churned dirs. Instrument the barrier + the
   sf↔block conversion path (P42-SFCONV) cross-node.
2. If fb=0 viable, VERIFY fb=0 across the WHOLE ladder (1/2/8/16/32 caw) — must not regress other
   tests. sess67 chose fb=1 default because 2/tcp passed 17/17 at fb=1; confirm fb=0 doesn't break
   2/8/16/32-caw before flipping the default `int mxfs_dir_force_block` (xfs_mxfs_dlm.c:7908).
3. Flip the default to 0 only after full-ladder validation.

### CAVEAT
Do NOT declare victory on cache_coherency from this single fb=0 PASS — require 3 consecutive clean
runs (sess117 variance rule). But the A/B is a strong, repeatable signal (2 tests PASS 4/4 clean,
fast: iso 16:20:07 + 16:20:14, seconds apart).
Build B6F0D45F (P-AGLOW probes, remove before final). Cluster: 4 nodes mounted fb=0 after the stall.
</body>
