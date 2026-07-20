---
name: sess29-BREAKTHROUGH-dir_reuse-8tcp-4of4-relinval-clean
description: sess29(ccloop) BREAKTHROUGH: dir_reuse_coherency 8/tcp PASSES 5/5 with dir_release_invalidate=1 + dir_relinval_clean=1 (build D1DD1926). Closes the r…
metadata:
  type: project
---

## sess29 — dir_reuse_coherency 8/tcp now PASSES reliably (5/5)

### Winning config (build D1DD1926E3781EB38F9BBAF)
`MXFS_EXTRA_MODARGS="dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1"`
- drc_passrate2.sh 4 → **4 PASS / 0 FAIL** (+ 1 earlier standalone PASS = 5/5). Each ~352-370s (well under the 480s budget).
- ZERO shutdowns (release_invalidate eliminated the DABUF_HOLE + xfs_defer shutdowns that plagued the baseline — they were stale-leaf/extent-map artifacts).

### The two fixes that did it (GPT-5.5 RULE-5 architecture: "no old-epoch buffer reaches disk after the DLM lock is released; invalidate ALL dir-fork buffers at release; plain cold-read on reacquire; FUA is NOT a coherency primitive")
1. **dir_release_invalidate=1** (EXISTING lever, sess13/19): on dir EX release, xfs_buf_stale() every clean+durable dir DATA/LEAF buffer it FLUSHES → next acquire cold-reads coherent. Alone = 1 PASS / 3 FAIL (residual single-dirent 799/800 loss + lookup_fail=0). Fixes leaf-content staleness (lookup_fail→0) AND the shutdowns.
2. **dir_relinval_clean=1** (NEW this session, xfs/xfs_mxfs_dlm.c in mxfs_dir_flush_data_blocks `!needs_flush` branch): release_invalidate only staled blocks it FLUSHED; a CLEAN cached but PEER-STALE block (needs_flush=0) was KEPT across the EX handoff → next acquirer served/RMW'd it stale → dropped a peer's add = the residual 799 loss. Fix: also xfs_buf_stale() clean (XBF_DONE, !dirty !in_ail !pin !delwri) cached dir blocks at release (loss-safe: no un-landed work). This CLOSED the residual → 4/4.

### REFUTED this session (do NOT pursue)
- **dir_write_merge** (my chokepoint 3-way data-block graft): helps count but creates CROSS-BLOCK DUPLICATE names (+1/+2 over-count, readdir 801/802) — can't verify global name-uniqueness from a single block at the bio chokepoint. FUA→plain read did NOT fix it. ABANDONED (default 0, code kept/gated). The relinval_clean read-side fix is strictly better.
- **dir_postread_reread=1**: catastrophic (all nodes shut down round 1, FUA leaf re-read tears).

### NEXT (to meet criteria 1/2/4/8 tcp 100%)
1. Validate FULL 8/tcp suite (all 17 tests) with these 4 modargs (dir_reuse passing standalone ≠ full suite — broad flakiness history).
2. If full suite green: make the 4 levers MODULE DEFAULTS (dir_gen_per_handoff, dir_modify_extent_adopt, dir_release_invalidate, dir_relinval_clean all default 1) so bare `./run.sh {1,2,4,8} tcp` (no modargs) passes.
3. Re-verify 1/2/4 tcp + 8/tcp full suite with the new DEFAULTS.
See [[sess29-GPT-architecture-release-invalidate-is-key-shutdowns-are-wall]] [[sess19run-PROGRESS-dir-release-levers-cut-lowmht-loss-18to4]].
