---
name: sess6-ccloop-FIX-gg-refresh-wholeblock-loss-10of12
description: sess6(run6614) FIX build 8AEAC90F: dir_gg_refresh=1 (arm evict-only refresh on grant_gen change) → dir_reuse 4/tcp 10/12, whole-block loss GONE. 2/tc…
metadata:
  type: project
---

## sess6 (run 6614) — FIX: grant_gen-triggered evict-only dir refresh (build 8AEAC90F)

### THE FIX (xfs_mxfs_dlm.c, KEEP unless regresses):
New default-ON param `mxfs_dir_gg_refresh=1`. On the dir-EX fast-path serve, arm `dir_ex_stale_refresh` whenever the per-grant token advanced (`hgg != ip->i_dlm_cached_grant_gen`) — the RELIABLE "lock changed hands" signal. Inserted at xfs_mxfs_dlm.c ~14862 (right before `cached_grant_gen` is updated), inside the `S_ISDIR && mode==EX && multinode` block after spin_unlock.
- **Why it works**: the existing fast-path refresh was armed by the master's dg_shadow handoff bit (lk->handoff), which sess13/sess53 proved UNDER-FIRES ~80% on TCP (P51-HANDOFF-UNDERFIRE). grant_gen is reliable (always advances on any re-grant episode).
- **Why it's loss-safe**: does NOT set dir_ex_handoff (so reload keeps post_release=false = keep-stale guards; no disk-adopt that would revert uncommitted work). It only triggers `mxfs_dir_drain_evict_data_blocks` which EVICTS clean/destaged blocks and SKIPS undestaged/dirty/pinned (our in-flight work). On a re-affirm-while-holding (grant_gen also advances — the sess63 over-fire root) our dirty blocks are kept; on a real cross-node re-grant our work was drained durable so cold-read gets the peer's superset. Reliable AND safe in both cases.

### RESULT (build 8AEAC90F, default modargs):
- **2/tcp = 17/17** (re-verified, NO regression).
- **1/tcp = 16/16** (from earlier: was disk-space env, fixed).
- **4/tcp dir_reuse = 10/12 reliability** (drc_reliability 4 12). Baseline was ~flaky-fail. **The 100-entry WHOLE-BLOCK loss (node2's entire contribution) is ELIMINATED.**
- Residual 2/12 FAILs = FINE single-dirent leaf-hash loss: readdir=400/400 lookup_fail=1 missing=[node2_f47] (a single LEAF hash entry gone, data present), or tiny undercount 399/386. NO shutdown (the "count 3" in dmesg was normal "DLM shutting down" unmounts, not corruption).

### NEXT (RULE 4): close the residual single-dirent LEAF-hash loss. drain_evict_data_blocks DOES walk all data-fork extents incl leaf blocks (for_each_xfs_iext), so leaf is evicted — but the residual is likely an UNDESTAGED-leaf SKIP: a leaf block in-AIL/dirty/pinned (our own prior-op in-flight leaf write) is kept by drain_evict, and it's a stale base missing a peer's committed hash → next addname RMW drops it. OR MXFS_DIR_DRAIN_MAX=64 cap (not hit at 400 entries). Investigate the leaf-block RMW base coherence specifically (xfs_dir2_leaf/node addname). sess20 fixed a leaf DABUF_MAP_HOLE via postread-leaf-only; leaf re-read is regression-prone. Consider: the 10-then-2 pattern may be cluster-state accumulation over 12 resets w/o reboot — retest with fresh virsh reboot to see if residual is lower.
See [[sess6-ccloop-REFUTED-phantomEX-progress-1and2tcp-100pct]]</body>
