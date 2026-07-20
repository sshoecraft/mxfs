---
name: sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12
description: sess6(run6614) dir_reuse 4/tcp FIXED 12/12: dir_gg_refresh=1 + dir_release_flush_leaf=1 (both now DEFAULT). build 9AA569A0. Verifying full suites 1/2…
metadata:
  type: project
---

## sess6 (run 6614) — dir_reuse_coherency FIXED at 4/tcp (12/12), build 9AA569A0

### TWO-PART FIX (both now DEFAULT-ON in xfs_mxfs_dlm.c):
1. **`mxfs_dir_gg_refresh=1`** (NEW, ~line 3990 + arming ~14862): arm the loss-safe EVICT-ONLY dir base refresh (mxfs_dir_drain_evict_data_blocks) on every grant_gen change (`hgg != cached_grant_gen`) — the RELIABLE "lock changed hands" signal (the dg_shadow handoff bit under-fires ~80% on TCP). dir_ex_handoff stays false → no disk-adopt → no revert of uncommitted work. Fixes the WHOLE-BLOCK (100-entry) data loss. Alone = 10/12.
2. **`mxfs_dir_release_flush_leaf=1`** (was SILENTLY 0 — the sess48 "DEFAULT 1" comment lied, initializer missing; now `= 1` at ~line 4286): force-complete LEAF/NODE/FREE dir index blocks at release (mxfs_dir_flush_one_daddr) so the next acquirer cold-reads a SELF-CONSISTENT data fork. Fixes the residual single-dirent LEAF-hash hole (readdir=400 lookup_fail=1 node2_f47). SAFE + REQUIRED with gg_refresh: gg_refresh gives a fresh leaf base each handoff so force-completing OUR (peer-superset+our-adds) leaf cannot revert a peer's hash (the sess22/sess48 "leaf force-write reverts peer hash" harm was WITHOUT acquire-side leaf eviction).

### EVIDENCE (drc_reliability 4 12):
- gg_refresh alone: 10/12 (residual = single leaf-hash hole).
- gg_refresh + release_flush_leaf: **12/12** ✓
- Each run = fresh mkfs (distinct UUIDs) + module reload, so genuine.
- REFUTED on top of gg_refresh: dir_tenure_evict=1 (regressed, run2 FAIL + shutdown face — DABUF_MAP_HOLE leaf flood, do NOT combine).

### STILL TO VERIFY (next steps, build 9AA569A0 default modargs):
- 2/tcp full 17/17 (gg_refresh already re-verified 17/17 on prior build 8AEAC90F; re-confirm with flush_leaf too).
- 1/tcp 16/16 (disk-space env fixed earlier; re-confirm).
- 4/tcp FULL suite (all 17, in-suite, default) — confirm dir_reuse passes in-suite + no regression.
- Longer 4/tcp dir_reuse reliability (15-20 runs) for confidence.
- 8/tcp FULL suite (unrun). If 8/tcp dir_reuse needs more (more nodes = more contention), same levers.
- If all of 1/2/4/8 tcp = 100% → write criteria-met marker.
See [[sess6-ccloop-FIX-gg-refresh-wholeblock-loss-10of12]] [[sess6-ccloop-REFUTED-phantomEX-progress-1and2tcp-100pct]]</body>
